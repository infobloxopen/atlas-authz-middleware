package authorizer

import "context"

// OpaEvaluator implements calling OPA with a request and receiving the raw response
type OpaEvaluator func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

type ClaimsVerifier func([]string, []string) (string, []error)

// Authorizer interface is implemented for making arbitrary requests to Opa.
type Authorizer interface {
	// Evaluate is called with the grpc request's method passing the grpc request Context.
	// If the handler is executed, the request will be sent to Opa. Opa's response
	// will be unmarshaled using JSON into the provided response.
	// Evaluate returns true if the request is authorized. The context
	// will be passed to subsequent HTTP Handler.
	Evaluate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes query of the specified decisionDocument against OPA.
	// If decisionDocument is "", then the query is executed against the default decision document configured in OPA.
	OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error
	
	AffirmAuthorization(ctx context.Context, fullMethod string, eq interface{}) (context.Context, error)
}
