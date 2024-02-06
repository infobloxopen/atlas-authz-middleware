package exception

import (
	"fmt"
)

var (
	//abstract errors
	ErrAbstrForbidden           = generateAbstrErr("request forbidden", "not authorized")
	ErrAbstrUnknown             = generateAbstrErr("unknown", "unknown error")
	ErrAbstrInvalidArg          = generateAbstrErr("invalid", "invalid argument")
	ErrAbstrInvalidEndpoint     = generateAbstrErr("invalid", "invalid endpoint to parse")
	ErrAbstrServiceUnavailable  = generateAbstrErr("serviceUnvailable", "connection refused")
	ErrAbstrInternal            = generateAbstrErr("internal", "internal error")
	ErrAbstrAuthHeaderMissing   = generateAbstrErr("authHeaderMissing", "Authorization header is missing")
	ErrAbstrAuthHeaderMalformed = generateAbstrErr("authHeaderMalformed", "Authorization header is malformed")
)

func generateAbstrErr(code, msg string) error {
	return fmt.Errorf("code: %s, message: %s", code, msg)
}
