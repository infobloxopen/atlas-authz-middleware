package authorizer

import "context"

// OpaEvaluator implements calling OPA with a request and receiving the raw response
type OpaEvaluator func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

type ClaimsVerifier func([]string, []string) (string, []error)

// Authorizer interface is implemented for making arbitrary requests to Opa.
type Authorizer interface {
	// Evaluate evaluates the authorization policy for the given request.
	// It takes the context, full method name, request object, and an OpaEvaluator as input.
	// It returns a boolean indicating whether the request is authorized, a modified context,
	// and an error if any.
	Evaluate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes a query against the OPA (Open Policy Agent) with the specified decision document.
	// If the decision document is an empty string, the query is executed against the default decision document
	// configured in OPA.
	// It takes the context, decision document name, OPA request object, and OPA response object as input.
	// It returns an error if any.
	OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

	AffirmAuthorization(ctx context.Context, fullMethod string, eq interface{}) (context.Context, error)
}
