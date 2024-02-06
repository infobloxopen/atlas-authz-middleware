package util

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/infobloxopen/atlas-app-toolkit/requestid"
	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
)

// GetRequestIdFromRequest fetches requestid from http request
func GetRequestIdFromRequest(r *http.Request) string {
	reqId := r.Header.Get(requestid.DefaultRequestIDKey)
	if len(reqId) != 0 {
		return reqId
	}
	return uuid.NewString()
}

// GetBearerFromRequest fetches requestid from http request
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
