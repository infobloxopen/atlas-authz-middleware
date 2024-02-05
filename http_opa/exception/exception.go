package exception

import (
	"fmt"
)

var (
	// ErrAbstrForbidden is an abstract error indicating that the request is forbidden and not authorized.
	ErrAbstrForbidden = generateAbstrErr("request forbidden", "not authorized")

	// ErrAbstrUnknown is an abstract error indicating an unknown error occurred.
	ErrAbstrUnknown = generateAbstrErr("unknown", "unknown error")

	// ErrAbstrInvalidArg is an abstract error indicating an invalid argument was provided.
	ErrAbstrInvalidArg = generateAbstrErr("invalid", "invalid argument")

	// ErrAbstrInvalidEndpoint is an abstract error indicating an invalid endpoint to parse.
	ErrAbstrInvalidEndpoint = generateAbstrErr("invalid", "invalid endpoint to parse")

	// ErrAbstrServiceUnavailable is an abstract error indicating that the service is unavailable and the connection was refused.
	ErrAbstrServiceUnavailable = generateAbstrErr("serviceUnvailable", "connection refused")

	// ErrAbstrInternal is an abstract error indicating an internal error occurred.
	ErrAbstrInternal = generateAbstrErr("internal", "internal error")

	// ErrAbstrAuthHeaderMissing is an abstract error indicating that the Authorization header is missing.
	ErrAbstrAuthHeaderMissing = generateAbstrErr("authHeaderMissing", "Authorization header is missing")

	// ErrAbstrAuthHeaderMalformed is an abstract error indicating that the Authorization header is malformed.
	ErrAbstrAuthHeaderMalformed = generateAbstrErr("authHeaderMalformed", "Authorization header is malformed")
)

// generateAbstrErr generates an abstract error with the given code and message.
func generateAbstrErr(code, msg string) error {
	return fmt.Errorf("code: %s, message: %s", code, msg)
}
