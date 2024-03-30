# Iris-Keycloak


Iris-Keycloak is specially made for [Iris Framework](https://github.com/kataras/iris)
users who also want to use Keycoak.
This Project was inspired by zalando's Gin-OAuth and forked from https://github.com/tbaehler/gin-keycloak


## Project Context and Features

When it comes to choosing a Go framework, there's a lot of confusion
about what to use. The scene is very fragmented, and detailed
comparisons of different frameworks are still somewhat rare. Meantime,
how to handle dependencies and structure projects are big topics in
the Go community. We've liked using Gin for its speed,
accessibility, and usefulness in developing microservice
architectures. In creating iris-OAuth2, we wanted to take fuller
advantage of Gin's capabilities and help other devs do likewise.

Iris-Keycloak is expressive, flexible, and very easy to use. It allows you to:
- do OAuth2 authorization based on the JWT Token
- create router groups to place Keycloak authorization on top, using HTTP verbs and passing them
- more easily decouple services by promoting a "say what to do, not how to do it" approach
- configure your REST API directly in the code (see the "Usage" example below)
- write your own authorization functions

## Requirements

- [Iris](https://github.com/kataras/iris)
- An Keycloak Token provider

Iris-Keycloak uses the following [Go](https://golang.org/) packages as
dependencies:

* [Iris](https://github.com/kataras/iris)
* [golog](https://github.com/kataras/golog)

## Installation

Assuming you've installed Go and Gin, run this:

    go get github.com/Dexus/iris-keycloak

## Usage

### Change Logging Level
    iriskeycloak.Logger.SetLevel("debug") // default debug

### Authentication-Based Access

With this function you just check if user is authenticated. Therefore there is no need for AccessTuple unlike next two access types.

Iris middlewares you use:

    app := iris.New()
    app.Use(iriskeycloak.RequestLogger([]string{"uid"}, "data"))


A Keycloakconfig. You can either use URL and Realm or define a fullpath that point to protocol/openid-connect/certs

    var sbbEndpoint = iriskeycloak.KeycloakConfig{
        Url:  "https://keycloack.domain.ch/",
        Realm: "Your Realm",
        FullCertsPath: nil
    }

Lastly, define which type of access you grant to the defined
team. We'll use a router group again:


    privateGroup := app.Party("/api/privateGroup")
    privateGroup.Use(iriskeycloak.Auth(iriskeycloak.AuthCheck(), keycloakconfig))
    privateGroup.Get("/", func(c iris.Context) {
    	....
    })

Once again, you can use curl to test:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to Dexus member of teapot"}


### Uid-Based Access

Restrict all access but for a few users

    config := iriskeycloak.BuilderConfig{
              		service:              <yourServicename>,
              		url:                  "<your token url>",
              		realm:                "<your realm to get the public keys>",
              }

    app := iris.New()
    privateUser := app.Party("/api/privateUser")

    privateUser.Use(iriskeycloak.NewAccessBuilder(config).
        RestrictButForUid("domain\user1").
        RestrictButForUid("domain\user2").
        Build())

    privateUser.Get("/", func(c iris.Context) {
    	....
    })

#### Testing

To test, you can use curl:

        curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateUser/
        {"message":"Hello from private for users 1+2"}

### Role-Based Access

Restrict all access but for the given roles


    config := iriskeycloak.BuilderConfig{
                  		service:              <yourServicename>,
                  		url:                  "<your token url>",
                  		realm:                "<your realm to get the public keys>",
                  }

    app := iris.New()
    privateUser := app.Party("/api/privateUser")

    privateUser.Use(iriskeycloak.NewAccessBuilder(config).
        RestrictButForRole("role1").
        RestrictButForRole("role2").
        Build())

    privateUser.Get("/", func(c iris.Context) {
    	....
    })

Once again, you can use curl to test:

    curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/privateGroup/
        {"message":"Hello from private to sszuecs member of teapot"}

### Realm-Based Access

Realm Based Access is also possible and straightforward:


    config := iriskeycloak.BuilderConfig{
                      		service:              <yourServicename>,
                      		url:                  "<your token url>",
                      		realm:                "<your realm to get the public keys>",
                      }

    app := iris.New()
    privateUser := app.Party("/api/privateUser")

    privateUser.Use(iriskeycloak.NewAccessBuilder(config).
        RestrictButForRealm("realmRole").
        Build())

    privateUser.Get("/", func(c iris.Context) {
    	....
    })


## Custom Claims Mapper

It is possible to configure a custom claims mapper to add to the `KeyCloakToken` custom claims that are not standard for KeyCloak tokens. The custom claims can be added to the provided field `CustomClaims`.

Here a simple example:

    type MyCustomClaims struct {
        Tenant string `json:"https://your-realm/tenant,omitempty"`
    }

    func MyCustomClaimsMapper(jsonWebToken *jwt.JSONWebToken, keyCloakToken *iriskeycloak.KeyCloakToken) error {
        claims := MyCustomClaims{}
        jsonWebToken.UnsafeClaimsWithoutVerification(&claims)
        keyCloakToken.CustomClaims = claims
        return nil
    }

    var keycloakconfig = iriskeycloak.KeycloakConfig{
        Url:                "https://keycloack.domain.ch/"
        Realm:              "your-realm",
        FullCertsPath:      nil,
        CustomClaimsMapper: MyCustomClaimsMapper,
    }

## FAQ

#### Which Token Signature Algorithms are currently supported?
Currently, are only "EC" (which uses keycloak by default) and "RS" supported

#### How to get the keycloak claims e.g. sub, mail, name?

        irisToken,_ := context.Get("token")
        token := irisToken.(iriskeycloak.KeyCloakToken)


## Contributors

Thanks to:

- Zalando Team for their initial work
- @thaehler for his https://github.com/tbaehler/gin-keycloak

## License

See MIT-License [LICENSE](LICENSE) file.
