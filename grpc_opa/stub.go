package grpc_opa_middleware

import (
	"github.com/infobloxopen/atlas-authz-middleware/common"
	"github.com/infobloxopen/atlas-authz-middleware/common/claim"
)

func NullClaimsVerifier(inp1 []string, inp2 []string) (string, []error) {
	return claim.NullClaimsVerifier(inp1, inp2)
}

func UnverifiedClaimFromBearers(bearer, newBearer []string) (string, []error) {
	return claim.UnverifiedClaimFromBearers(bearer, newBearer)
}

func IsNilInterface(i interface{}) bool {
	return common.IsNilInterface(i)
}
