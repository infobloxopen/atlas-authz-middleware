package httpopa

import (
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/exception"
)

type ContextKey string

var (
	EndPointKey = ContextKey("endpoint")
)


// NewServerAuthzMiddleware is a middleware function that performs authorization checks for incoming HTTP requests.
// It takes an application name and optional authorizer options as parameters.
// The returned middleware function wraps the provided http.Handler and performs authorization checks before passing the request to the next handler.
// If the authorization check fails, it returns an HTTP error response.
// The middleware uses the OPA (Open Policy Agent) query language to evaluate the authorization rules.
// It iterates over a list of authorizers and stops at the first authorizer that returns a successful authorization result.
// If none of the authorizers return a successful result, it returns an HTTP error response indicating that the request is not authorized.
// The middleware logs any errors that occur during the authorization process.
func NewServerAuthzMiddleware(application string, opts ...authorizer.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			cfg := authorizer.NewDefaultConfig(application, opts...)
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
