package authorizer

import (
	"context"
)

// OpaEvaluator implements calling OPA with a request and receiving the raw response
type OpaEvaluator func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

type ClaimsVerifier func([]string, []string) (string, []error)

// AcctEntitlementsType is a convenience data type, returned by GetAcctEntitlements()
// (map of acct_id to map of service to array of features)
type AcctEntitlementsType map[string]map[string][]string

// FilterCompartmentPermissionsType is a convenience data type, returned by FilterCompartmentPermissions()
// (map of application to array of permissions)
type FilterCompartmentPermissionsType []string

// FilterCompartmentFeaturesType is a convenience data type, returned by FilterCompartmentFeatures()
// (map of application to array of feature)
type FilterCompartmentFeaturesType map[string][]string

// Authorizer interface is implemented for making arbitrary requests to Opa.
type Authorizer interface {
	// Validate evaluates the authorization policy for the given request.
	// It takes the context, full method name, request object, and an OpaEvaluator as input.
	// Unlike Evaluate, it only returns the raw Opa response, it does not parse the results.
	Validate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (interface{}, error)

	// Evaluate evaluates the authorization policy for the given request.
	// It takes the context, full method name, request object, and an OpaEvaluator as input.
	// It parses the Opa response and returns a boolean indicating whether the request is authorized,
	// a modified context, and an error if any.  It also parses and adds the entitled_features and obligations
	// from Opa response in the modified context returned.
	Evaluate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes a query against the OPA (Open Policy Agent) with the specified decision document.
	// If the decision document is an empty string, the query is executed against the default decision document
	// configured in OPA.
	// It takes the context, decision document name, OPA request object, and OPA response object as input.
	// It returns an error if any.
	OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

	AffirmAuthorization(ctx context.Context, fullMethod string, eq interface{}) (context.Context, error)

	GetAcctEntitlements(ctx context.Context, accountIDs, serviceNames []string) (*AcctEntitlementsType, error)

	GetCurrentUserCompartments(ctx context.Context) ([]string, error)

	FilterCompartmentPermissions(ctx context.Context, permissions FilterCompartmentPermissionsType) (FilterCompartmentPermissionsType, error)

	FilterCompartmentFeatures(ctx context.Context, features FilterCompartmentFeaturesType) (FilterCompartmentFeaturesType, error)
}
