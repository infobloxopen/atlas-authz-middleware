module github.com/Infoblox-CTO/ngp.authz/pkg/grpc_opa_middleware

go 1.14

require (
	cloud.google.com/go v0.57.0 // indirect
	github.com/Infoblox-CTO/athena-authn-claims v1.0.15
	github.com/Infoblox-CTO/ngp.authz/pkg/opa_client v0.0.0-20200514160843-aeab1110c85a
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2
	github.com/sirupsen/logrus v1.7.0
	go.opencensus.io v0.22.5
	google.golang.org/grpc v1.34.0
	google.golang.org/grpc/examples v0.0.0-20201209011439-fd32f6a4fefe // indirect
)

replace github.com/Infoblox-CTO/ngp.authz/pkg/opa_client => ../opa_client
