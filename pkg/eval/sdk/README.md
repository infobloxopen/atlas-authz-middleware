
# Integration Guidelines

```go
	import authz_fl "github.com/infobloxopen/atlas-authz-middleware/pkg/eval/wasm"

	interceptors = append(interceptors, authz_fl.UnaryServerInterceptor(
		authz_fl.ForApplicaton(appID),
		authz_fl.WithLogger(logger),
		authz_fl.WithBundleResourcePath("/bundle/bundle.tar.gz"),
		authz_fl.WithDecisionPath("/authz/rbac/validate_v1"),
	))
```

# Benchmarking

Run 

```go

go test -bench=Autorizer_Authorize -benchtime=10s -run=dontrunanytests -benchmem

```

