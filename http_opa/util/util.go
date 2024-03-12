package util

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
)

const (
	DefaultRequestIDKey     = "X-Request-ID"
	BearerPrefix            = "Bearer "
	AuthorizationHeaderName = "Authorization"
)

// GetRequestIdFromRequest fetches requestid from http request
func GetRequestIdFromRequest(r *http.Request) string {
	reqId := r.Header.Get(DefaultRequestIDKey)
	if len(reqId) != 0 {
		return reqId
	}
	return uuid.NewString()
}

// GetBearerFromRequest fetches the first available bearer token from the request header.
func GetBearerFromRequest(r *http.Request) (string, error) {
	authHead := r.Header.Values(AuthorizationHeaderName)
	for _, auth := range authHead {
		token, isBearer := strings.CutPrefix(auth, BearerPrefix)
		if isBearer {
			return token, nil
		}
	}

	return "", exception.ErrAbstrAuthHeaderMissing
}
