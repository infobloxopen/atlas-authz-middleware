package util

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/infobloxopen/atlas-app-toolkit/requestid"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/exception"
)

// GetRequestIdFromRequest retrieves the request ID from the given HTTP request.
// If the request already contains a request ID in the header, it returns that.
// Otherwise, it generates a new request ID using UUID and returns it.
func GetRequestIdFromRequest(r *http.Request) string {
	reqId := r.Header.Get(requestid.DefaultRequestIDKey)
	if len(reqId) != 0 {
		return reqId
	}
	return uuid.NewString()
}


// GetBearerFromRequest extracts the bearer token from the Authorization header of an HTTP request.
// It returns the bearer token as a string and an error if the header is missing or malformed.
func GetBearerFromRequest(r *http.Request) (string, error) {
	authHead := r.Header.Get("Authorization")
	if len(authHead) == 0 {
		return authHead, exception.ErrAbstrAuthHeaderMissing
	}
	authHeadArr := strings.Split(authHead, " ")
	if len(authHeadArr) != 2 {
		return authHead, exception.ErrAbstrAuthHeaderMalformed
	}
	return authHeadArr[1], nil
}
