package authorizer

import (
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// OpaqueError trims some privileged information from errors
// as these get sent directly as grpc responses
func OpaqueError(err error) error {

	switch status.Code(err) {
	case codes.Unavailable:
		return opa_client.ErrServiceUnavailable
	case codes.Unknown:
		return opa_client.ErrUnknown
	}

	return err
}
