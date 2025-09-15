module example.com/http-jwks

go 1.24.7

require (
	github.com/auth0/go-jwt-middleware/v2 v2.2.2
	github.com/go-jose/go-jose/v4 v4.1.2
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require (
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
)
