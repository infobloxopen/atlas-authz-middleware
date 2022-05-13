package wasm

type OptHub struct {
	*Config
	Authorizers []Authorizer
}

type Option func(c *OptHub)

// WithAuthorizer ...
func WithAuthorizer(authers ...Authorizer) Option {
	return func(c *OptHub) {
		c.Authorizers = authers
	}
}

// ForApplicaton ...
func ForApplicaton(app string) Option {
	return func(c *OptHub) {
		c.applicaton = app
	}
}

func WithDecisionPath(path string) Option {
	return func(c *OptHub) {
		c.decisionPath = path
	}
}

// WithDecisionInputHandler supplies optional DecisionInputHandler
// for DefaultAuthorizer to obtain additional input for OPA
// ABAC decision processing.
func WithDecisionInputHandler(decisionHandler DecisionInputHandler) Option {
	return func(c *OptHub) {
		c.decisionInputHandler = decisionHandler
	}
}

// WithClaimsVerifier overrides default ClaimsVerifier
func WithClaimsVerifier(claimsVerifier ClaimsVerifier) Option {
	return func(c *OptHub) {
		c.claimsVerifier = claimsVerifier
	}
}

// WithEntitledServices overrides default EntitledServices
func WithEntitledServices(entitledServices ...string) Option {
	return func(c *OptHub) {
		c.entitledServices = entitledServices
	}
}

// WithAcctEntitlementsApiPath overrides default AcctEntitlementsApiPath
func WithAcctEntitlementsApiPath(acctEntitlementsApi string) Option {
	return func(c *OptHub) {
		c.acctEntitlementsApi = acctEntitlementsApi
	}
}
