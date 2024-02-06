package authorizer

import "context"

// DecisionInput is app/service-specific data supplied by app/service ABAC requests
type DecisionInput struct {
	Type             string        `json:"type"` // Object/resource-type to match
	Verb             string        `json:"verb"` // Verb to match
	SealCtx          []interface{} `json:"ctx"`  // Array of app/service-specific context data to match
	DecisionDocument string        `json:"-"`    // OPA decision document to query, by default "",
	// which is default decision document configured in OPA
}

// fullMethod is of the form "Service.FullMethod"
type DecisionInputHandler interface {
	// GetDecisionInput returns an app/service-specific DecisionInput.
	// A nil DecisionInput should NOT be returned unless error.
	GetDecisionInput(ctx context.Context, fullMethod string, req interface{}) (*DecisionInput, error)
}

// DefaultDecisionInputer is an example DecisionInputHandler that is used as default
type DefaultDecisionInputer struct{}

func (m DefaultDecisionInputer) String() string {
	return "authorizer.DefaultDecisionInputer{}"
}

// GetDecisionInput is an example DecisionInputHandler that returns some decision input
// based on some incoming Context values.  App/services will most likely supply their
// own DecisionInputHandler using WithDecisionInputHandler option.
func (m *DefaultDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error) {
	var abacType string
	if v, ok := ctx.Value(TypeKey).(string); ok {
		abacType = v
	}

	var abacVerb string
	if v, ok := ctx.Value(VerbKey).(string); ok {
		abacVerb = v
	}

	decInp := DecisionInput{
		Type: abacType,
		Verb: abacVerb,
	}
	return &decInp, nil
}
