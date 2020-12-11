package opa_client

import (
	"net/http"

	"github.com/open-policy-agent/opa/server/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Opaque errors to reveal less details in upstream client
	ErrServiceUnavailable = types.NewErrorV1("SeviceUnavailable", "connection refused")
	ErrUnknown            = types.NewErrorV1("Unknown", "unknown error")
)

// ErrorV1 implements missing errors.Unwrap functionality
// TODO: issue opened with OPA https://github.com/open-policy-agent/opa/issues/2633
type ErrorV1 struct {
	types.ErrorV1
	Err error
}

// NewErrorV1 returns *ErrorV1
func NewErrorV1(code string, err error) *ErrorV1 {
	return &ErrorV1{
		ErrorV1: types.ErrorV1{
			Code:    code,
			Message: err.Error(),
		},
		Err: err,
	}
}

// Unwrap allows embedding errors within ErrorV1
func (e *ErrorV1) Unwrap() error {
	return e.Err
}

func grpcCodeFromOPACode(code string) codes.Code {
	switch code {
	// No string appears to mean no error
	case "":
		return codes.OK
	case types.CodeInternal:
		return codes.Internal
	case types.CodeEvaluation:
		return codes.Internal
	case types.CodeUnauthorized:
		return codes.PermissionDenied
	case types.CodeInvalidParameter:
		return codes.InvalidArgument
	case types.CodeInvalidOperation:
		return codes.InvalidArgument
	case types.CodeResourceNotFound:
		return codes.NotFound
	case types.CodeResourceConflict:
		return codes.NotFound
	case types.CodeUndefinedDocument:
		return codes.NotFound
	// Also check against custom OPA Errors
	case http.StatusText(http.StatusServiceUnavailable):
		return codes.Unavailable
	}
	return codes.Unknown

}

func opaErrToGrpcErr(errV1 *types.ErrorV1) error {
	return status.Error(grpcCodeFromOPACode(errV1.Code), errV1.Message)
}

// GRPCError translates opa encodes errors to gRPC status errors
func GRPCError(err error) error {
	switch tErr := err.(type) {
	case *types.ErrorV1:
		return opaErrToGrpcErr(tErr)
	case *ErrorV1:
		return status.Error(grpcCodeFromOPACode(tErr.Code), tErr.Message)
	}

	return status.Error(codes.Unknown, err.Error())
}
