
[SDK](https://www.openpolicyagent.org/docs/latest/integration/#sdk)

# Integration Guidelines

```go
	import "github.com/infobloxopen/atlas-authz-middleware/pkg/eval/opasdk"

	interceptors = append(interceptors, opasdk.UnaryServerInterceptor(
        opasdk.ForApplicaton(appID),
        opasdk.WithLogger(logger),
        opasdk.WithBundleResourcePath("/bundle/bundle.tar.gz"),
        opasdk.WithDecisionPath("/authz/rbac/validate_v1"),
        opasdk.WithBundleReloadInterval(time.Minute),
	))
```

# Benchmarking

Run 

```go

go test -bench=Autorizer_Authorize -benchtime=10s -run=dontrunanytests -benchmem

```

