module example.com/http-jwks

go 1.23

require (
	github.com/auth0/go-jwt-middleware/v2 v2.1.0
	github.com/go-jose/go-jose/v4 v4.0.4
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require (
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/grpc v1.68.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
