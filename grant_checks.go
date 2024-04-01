package iriskeycloak

import "github.com/kataras/iris/v12"

type AccessCheckFunction func(tc *TokenContainer, ctx iris.Context) bool

type AccessTuple struct {
	Service string
	Role    string
	Uid     string
}

func GroupCheck(at []AccessTuple) func(tc *TokenContainer, ctx iris.Context) bool {
	ats := at
	return func(tc *TokenContainer, ctx iris.Context) bool {
		addTokenToContext(tc, ctx)
		for idx := range ats {
			at := ats[idx]
			if tc.KeyCloakToken.ResourceAccess != nil {
				serviceRoles := tc.KeyCloakToken.ResourceAccess[at.Service]
				for _, role := range serviceRoles.Roles {
					if role == at.Role {
						return true
					}
				}
			}
		}
		return false
	}
}

func RealmCheck(allowedRoles []string) func(tc *TokenContainer, ctx iris.Context) bool {

	return func(tc *TokenContainer, ctx iris.Context) bool {
		addTokenToContext(tc, ctx)
		for _, allowedRole := range allowedRoles {
			for _, role := range tc.KeyCloakToken.RealmAccess.Roles {
				if role == allowedRole {
					return true
				}
			}
		}
		return false
	}
}

func addTokenToContext(tc *TokenContainer, ctx iris.Context) {
	ctx.Values().Set("token", *tc.KeyCloakToken)
	ctx.Values().Set("oauth2token", *tc.Token)
	ctx.Values().Set("uid", tc.KeyCloakToken.PreferredUsername)
}

func UidCheck(at []AccessTuple) func(tc *TokenContainer, ctx iris.Context) bool {
	ats := at
	return func(tc *TokenContainer, ctx iris.Context) bool {
		addTokenToContext(tc, ctx)
		uid := tc.KeyCloakToken.PreferredUsername
		for idx := range ats {
			at := ats[idx]
			if at.Uid == uid {
				return true
			}
		}
		return false
	}
}

func AuthCheck() func(tc *TokenContainer, ctx iris.Context) bool {
	return func(tc *TokenContainer, ctx iris.Context) bool {
		addTokenToContext(tc, ctx)
		return true
	}
}
