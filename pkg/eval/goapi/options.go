package goapi

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
		c.Applicaton = app
	}
}

func WithDecisionPath(path string) Option {
	return func(c *OptHub) {
		c.DecisionPath = path
	}
}


