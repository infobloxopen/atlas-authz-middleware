package httpopa

import (
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"

	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
)

type ContextKey string

var (
	EndPointKey = ContextKey("endpoint")
)

// NewServerAuthzMiddleware evaluate the OPA policy against the requested endpoint, and aborts the request if not authorized.
func NewServerAuthzMiddleware(application string, opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			cfg := NewDefaultConfig(application, opts...)
			logger := ctxlogrus.Extract(ctx)

			var (
				ok  bool
				err error
			)

			authorizers := cfg.GetAuthorizer()
			for _, auther := range authorizers {
				//REVIEW: identify if returned ctx is needed or not
				ok, _, err = auther.Evaluate(ctx, getEndpoint(r), r, auther.OpaQuery)
				if err != nil {
					logger.WithError(err).WithField("authorizer", auther).Error("unable_authorize")
				}
				if ok {
					break
				}
			}
			if err != nil || !ok {
				if err == nil {
					err = exception.ErrUnknown
				}
				logger.WithError(err).Error("policy engine returned an error")
				he := err.(*exception.HttpError)
				http.Error(w, "unable to authorize", he.Status)
				return
			}

			next.ServeHTTP(w, r)

		})
	}
}

func getVerbAndEndpointHTTP(r *http.Request) string {
	return strings.Join([]string{r.Method, r.URL.Path}, " ")
}

func getEndpoint(r *http.Request) string {
	if ep, ok := r.Context().Value(EndPointKey).(string); ok {
		return ep
	}
	return getVerbAndEndpointHTTP(r)
}
