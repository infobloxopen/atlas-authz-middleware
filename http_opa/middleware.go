package http_opa

import (
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	grpc_opa_middleware "github.com/infobloxopen/atlas-authz-middleware/grpc_opa"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
)

// AuthzMiddleware evaluate the OPA policy against the requested endpoint, and aborts the request if not authorized.
func AuthzMiddleware(application string, opts ...grpc_opa_middleware.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			cfg := grpc_opa_middleware.NewDefaultConfig(application, opts...)
			logger := ctxlogrus.Extract(ctx)

			var (
				ok  bool
				err error
			)

			authorizers := cfg.GetAuthorizer()
			for _, auther := range authorizers {
				//TODO: identify if returned ctx is needed or not
				ok, _, err = auther.Evaluate(ctx, getVerbAndEndpointHTTP(r), nil, auther.OpaQuery)
				if err != nil {
					logger.WithError(err).WithField("authorizer", auther).Error("unable_authorize")
					http.Error(w, "unable to authorize", http.StatusForbidden)
					return
				}
				if ok {
					break
				}
			}
			if err != nil {
				logger.WithError(err).Error("unable_authorize")
				http.Error(w, "unable to authorize", http.StatusForbidden)
				return
			}

			if !ok {
				logger.WithError(opa_client.ErrUndefined).Error("policy engine returned undefined response")
				http.Error(w, "unable to authorize", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)

		})
	}
}

func getVerbAndEndpointHTTP(r *http.Request) string {
	return strings.Join([]string{r.Method, r.URL.Path}, " ")
}
