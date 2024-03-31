package iriskeycloak

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/kataras/golog"
	"github.com/kataras/iris/v12"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
)

var Logger = golog.New().SetLevel("debug")

var SignatureAlgorithm = []jose.SignatureAlgorithm{jose.RS256, jose.RS512, jose.ES512, jose.ES256, jose.EdDSA}

// VarianceTimer controls the max runtime of Auth() and AuthChain() middleware
var VarianceTimer = 30000 * time.Millisecond
var publicKeyCache = cache.New(8*time.Hour, 8*time.Hour)

// TokenContainer stores all relevant token information
type TokenContainer struct {
	Token         *oauth2.Token
	KeyCloakToken *KeyCloakToken
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("No authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("Incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func GetTokenContainer(token *oauth2.Token, config KeycloakConfig) (*TokenContainer, error) {

	keyCloakToken, err := decodeToken(token, config)
	if err != nil {
		return nil, err
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
		},
		KeyCloakToken: keyCloakToken,
	}, nil
}

func getPublicKey(keyId string, config KeycloakConfig) (interface{}, error) {
	keyEntry, err := getPublicKeyFromCacheOrBackend(keyId, config)
	if err != nil {
		return nil, err
	}
	if strings.ToUpper(keyEntry.Kty) == "RSA" {
		n, _ := base64.RawURLEncoding.DecodeString(keyEntry.N)
		bigN := new(big.Int)
		bigN.SetBytes(n)
		e, _ := base64.RawURLEncoding.DecodeString(keyEntry.E)
		bigE := new(big.Int)
		bigE.SetBytes(e)
		return &rsa.PublicKey{N: bigN, E: int(bigE.Int64())}, nil
	} else if strings.ToUpper(keyEntry.Kty) == "EC" {
		x, _ := base64.RawURLEncoding.DecodeString(keyEntry.X)
		bigX := new(big.Int)
		bigX.SetBytes(x)
		y, _ := base64.RawURLEncoding.DecodeString(keyEntry.Y)
		bigY := new(big.Int)
		bigY.SetBytes(y)

		var curve elliptic.Curve
		crv := strings.ToUpper(keyEntry.Crv)
		switch crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("EC curve algorithm not supported " + keyEntry.Kty)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     bigX,
			Y:     bigY,
		}, nil
	} else if strings.ToUpper(keyEntry.Kty) == "OKP" {

		var pKey ed25519.PublicKey
		pKey, _ = base64.RawURLEncoding.DecodeString(keyEntry.X)
		return pKey, nil
	}

	return nil, errors.New("no support for keys of type " + keyEntry.Kty)
}

func getPublicKeyFromCacheOrBackend(keyId string, config KeycloakConfig) (KeyEntry, error) {
	entry, exists := publicKeyCache.Get(keyId)
	if exists {
		return entry.(KeyEntry), nil
	}

	u, err := url.Parse(config.Url)
	if err != nil {
		return KeyEntry{}, err
	}

	if config.FullCertsPath != nil {
		u.Path = *config.FullCertsPath
	} else {
		u.Path = path.Join(u.Path, "realms", config.Realm, "protocol/openid-connect/certs")
	}

	resp, err := http.Get(u.String())
	if err != nil {
		return KeyEntry{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var certs Certs
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return KeyEntry{}, err
	}

	for _, keyIdFromServer := range certs.Keys {
		if keyIdFromServer.Kid == keyId {
			publicKeyCache.Set(keyId, keyIdFromServer, cache.DefaultExpiration)
			return keyIdFromServer, nil
		}
	}

	return KeyEntry{}, errors.New("No public key found with kid " + keyId + " found")
}

func decodeToken(token *oauth2.Token, config KeycloakConfig) (*KeyCloakToken, error) {
	keyCloakToken := KeyCloakToken{}

	var err error
	parsedJWT, err := jwt.ParseSigned(token.AccessToken, SignatureAlgorithm)
	if err != nil {
		Logger.Errorf("[iris-OAuth] jwt not decodable: %s", err)
		return nil, err
	}
	key, err := getPublicKey(parsedJWT.Headers[0].KeyID, config)
	if err != nil {
		Logger.Errorf("Failed to get publickey %v", err)
		return nil, err
	}

	err = parsedJWT.Claims(key, &keyCloakToken)
	if err != nil {
		Logger.Errorf("Failed to get claims JWT:%+v", err)
		return nil, err
	}

	if config.CustomClaimsMapper != nil {
		err = config.CustomClaimsMapper(parsedJWT, &keyCloakToken)
		if err != nil {
			Logger.Errorf("Failed to get custom claims JWT:%+v", err)
			return nil, err
		}
	}

	return &keyCloakToken, nil
}

func isExpired(token *KeyCloakToken) bool {
	if token.Exp == 0 {
		return false
	}
	now := time.Now()
	fromUnixTimestamp := time.Unix(token.Exp, 0)
	return now.After(fromUnixTimestamp)
}

func getTokenContainer(ctx iris.Context, config KeycloakConfig) (*TokenContainer, bool) {
	var oauthToken *oauth2.Token
	var tc *TokenContainer
	var err error

	if oauthToken, err = extractToken(ctx.Request()); err != nil {
		Logger.Errorf("[iris-OAuth] Can not extract oauth2.Token, caused by: %s", err)
		return nil, false
	}
	if !oauthToken.Valid() {
		Logger.Infof("[iris-OAuth] Invalid Token - nil or expired")
		return nil, false
	}

	if tc, err = GetTokenContainer(oauthToken, config); err != nil {
		Logger.Errorf("[iris-OAuth] Can not extract TokenContainer, caused by: %s", err)
		return nil, false
	}

	if isExpired(tc.KeyCloakToken) {
		Logger.Errorf("[iris-OAuth] Keycloak Token has expired")
		return nil, false
	}

	return tc, true
}

func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

type ClaimMapperFunc func(jsonWebToken *jwt.JSONWebToken, keyCloakToken *KeyCloakToken) error

type KeycloakConfig struct {
	Url                string
	Realm              string
	FullCertsPath      *string
	CustomClaimsMapper ClaimMapperFunc
}

func Auth(accessCheckFunction AccessCheckFunction, endpoints KeycloakConfig) iris.Handler {
	return authChain(endpoints, accessCheckFunction)
}

func authChain(config KeycloakConfig, accessCheckFunctions ...AccessCheckFunction) iris.Handler {
	// middleware
	return func(ctx iris.Context) {
		t := time.Now()
		varianceControl := make(chan bool, 1)

		go func() {
			tokenContainer, ok := getTokenContainer(ctx, config)
			if !ok {
				ctx.StopWithError(http.StatusUnauthorized, errors.New("No token in context"))
				varianceControl <- false
				return
			}

			if !tokenContainer.Valid() {
				ctx.StopWithError(http.StatusUnauthorized, errors.New("Invalid Token"))
				varianceControl <- false
				return
			}
			ctx.Values().Set("KeyCloakToken", tokenContainer.KeyCloakToken)
			for _, fn := range accessCheckFunctions {
				if fn(tokenContainer, ctx) {
					varianceControl <- true
					return
				}
			}
			ctx.StopWithError(http.StatusForbidden, errors.New("Access to the Resource is forbidden"))
			varianceControl <- false
		}()

		select {
		case ok := <-varianceControl:
			if !ok {
				Logger.Infof("[iris-OAuth] %12v %s access not allowed", time.Since(t), ctx.Request().URL.Path)
				return
			}
		case <-time.After(VarianceTimer):
			ctx.StopWithError(http.StatusGatewayTimeout, errors.New("Authorization check overtime"))
			Logger.Infof("[iris-OAuth] %12v %s overtime", time.Since(t), ctx.Request().URL.Path)
			return
		}
		Logger.Infof("[iris-OAuth] %12v %s access allowed", time.Since(t), ctx.Request().URL.Path)
		ctx.Next()
	}
}

func RequestLogger(keys []string, contentKey string) iris.Handler {
	return func(c iris.Context) {
		request := c.Request()
		c.Next()
		err := c.GetErr()
		if request.Method != "GET" && err == nil {
			if c.Values().Exists(contentKey) { //key is non existent
				data := c.Values().GetString(contentKey)
				values := make([]string, 0)
				for _, key := range keys {
					if c.Values().Exists(key) {
						values = append(values, c.Values().GetString(key))
					}
				}
				Logger.Infof("[iris-OAuth] Request: %+v for %s", data, strings.Join(values, "-"))
			}
		}
	}
}
