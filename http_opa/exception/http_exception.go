package exception

import (
	"net/http"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/open-policy-agent/opa/server/types"
)

// ErrForbidden is an HTTP error representing a forbidden request.
var ErrForbidden = NewHttpError(WithError(ErrAbstrForbidden), WithHttpStatus(http.StatusUnauthorized))

// ErrUnknown is an HTTP error representing an unknown error.
var ErrUnknown = NewHttpError(WithError(ErrAbstrUnknown), WithHttpStatus(http.StatusInternalServerError))

// ErrInvalidArg is an HTTP error representing an invalid argument.
var ErrInvalidArg = NewHttpError(WithError(ErrAbstrInvalidArg), WithHttpStatus(http.StatusBadRequest))

// ErrServiceUnavailable is an HTTP error representing a service unavailable.
var ErrServiceUnavailable = NewHttpError(WithError(ErrAbstrServiceUnavailable), WithHttpStatus(http.StatusServiceUnavailable))

// HttpError represents an HTTP error with a status code.
type HttpError struct {
	error
	Status int
}

// NewHttpError creates a new HttpError with the given options.
func NewHttpError(opts ...ErrOpt) *HttpError {
	he := &HttpError{
		Status: http.StatusInternalServerError,
		error:  ErrAbstrInternal,
	}
	for _, opt := range opts {
		opt(he)
	}
	return he
}

// ErrOpt is a function that modifies an HttpError.
type ErrOpt func(he *HttpError)

// WithHttpStatus sets the HTTP status code for an HttpError.
func WithHttpStatus(status int) ErrOpt {
	return func(he *HttpError) {
		he.Status = status
	}
}

// WithError sets the error message for an HttpError.
func WithError(err error) ErrOpt {
	return func(he *HttpError) {
		he.error = err
	}
}

// WithCode sets the HTTP status code for an HttpError based on an OPA code.
func WithCode(code string) ErrOpt {
	return WithHttpStatus(httpStatusFromOPACode(code))
}

// GrpcToHttpError translates OPA errors to HttpError.
func GrpcToHttpError(err error) *HttpError {
	switch tErr := err.(type) {
	case *types.ErrorV1:
		return opaErrTHttpErr(WithCode(tErr.Code), WithError(tErr))
	case *opa_client.ErrorV1:
		return opaErrTHttpErr(WithCode(tErr.Code), WithError(tErr))
	}
	return opaErrTHttpErr(WithError(err))
}

func opaErrTHttpErr(opts ...ErrOpt) *HttpError {
	return NewHttpError(opts...)
}

var codeToHttpStatus = map[string]int{
	"":                          http.StatusOK,
	types.CodeInternal:          http.StatusInternalServerError,
	types.CodeEvaluation:        http.StatusInternalServerError,
	types.CodeUnauthorized:      http.StatusUnauthorized,
	types.CodeInvalidParameter:  http.StatusBadRequest,
	types.CodeInvalidOperation:  http.StatusBadRequest,
	types.CodeResourceNotFound:  http.StatusNotFound,
	types.CodeResourceConflict:  http.StatusNotFound,
	types.CodeUndefinedDocument: http.StatusNotFound,
	http.StatusText(http.StatusServiceUnavailable): http.StatusServiceUnavailable,
}

func httpStatusFromOPACode(code string) int {
	if status, ok := codeToHttpStatus[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// AbstractError trims some privileged information from errors
// as these get sent directly as grpc responses.
func AbstractError(err *HttpError) *HttpError {
	switch err.Status {
	case http.StatusServiceUnavailable:
		return ErrServiceUnavailable
	}
	return err
}
