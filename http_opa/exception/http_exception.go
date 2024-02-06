package exception

import (
	"net/http"

	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/open-policy-agent/opa/server/types"
)

var (
	ErrForbidden          = NewHttpError(WithError(ErrAbstrForbidden), WithHttpStatus(http.StatusUnauthorized))
	ErrUnknown            = NewHttpError(WithError(ErrAbstrUnknown), WithHttpStatus(http.StatusInternalServerError))
	ErrInvalidArg         = NewHttpError(WithError(ErrAbstrInvalidArg), WithHttpStatus(http.StatusBadRequest))
	ErrServiceUnavailable = NewHttpError(WithError(ErrAbstrServiceUnavailable), WithHttpStatus(http.StatusServiceUnavailable))
)

type HttpError struct {
	error
	Status int
}

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

type ErrOpt func(he *HttpError)

func WithHttpStatus(status int) ErrOpt {
	return func(he *HttpError) {
		he.Status = status
	}
}

func WithError(err error) ErrOpt {
	return func(he *HttpError) {
		he.error = err
	}
}

func WithCode(code string) ErrOpt {
	return WithHttpStatus(httpStatusFromOPACode(code))
}

// HttpError translates opa errors to http status errors
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
// as these get sent directly as grpc responses
func AbstractError(err *HttpError) *HttpError {
	switch err.Status {
	case http.StatusServiceUnavailable:
		return ErrServiceUnavailable
	}
	return err
}
