### Direct (Non-GRPC-Interceptor) Usage

```go
import opamw "github.com/infobloxopen/atlas-authz-middleware/grpc_opa"

// Create Authorizer with example options
authzer := opamw.NewDefaultAuthorizer(
    viper.GetString("app.id"),
    opamw.WithAddress(opa_client.DefaultAddress),
    opamw.WithDecisionInputHandler(&myDecisionInputer{}),
)

// AffirmAuthorization makes an authz request to sidecar-OPA.
// If authorization is permitted, error returned is nil,
// and a new context is returned, possibly containing obligations.
// Caller must further evaluate obligations if required.
newCtx, err := authzer.AffirmAuthorization(ctx, "MyService.MyMethod", nil)

if err == nil {
    // Operation is permitted, fetch and process obligations
    if newCtx != nil {
        obVal := newCtx.Value(opamw.ObKey)
        if obVal != nil {
            obTree, ok := obVal.(opamw.ObligationsNode)
            if ok && obTree != nil  && !obTree.IsShallowEmpty() {
                // process any obligations in obTree if required
            }
        }
    }
}
```

### GRPC Unary Interceptor Usage

```go
import opamw "github.com/infobloxopen/atlas-authz-middleware/grpc_opa"

// Create unary-interceptor with example options
authzOpaInterceptor := opamw.UnaryServerInterceptor(
    viper.GetString("app.id"),
    opamw.WithAddress(opa_client.DefaultAddress),
    opamw.WithDecisionInputHandler(&myDecisionInputer{}),
)

interceptors = append(interceptors, authzOpaInterceptor)
```
