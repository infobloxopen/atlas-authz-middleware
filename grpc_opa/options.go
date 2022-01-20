package grpc_opa_middleware

import (
	"net/http"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
)

type Option func(c *Config)

// WithAddress
func WithAddress(address string) Option {
	return func(c *Config) {
		c.address = address
	}
}

// WithHTTPClient overrides the http.Client used to call Opa
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		if client != nil {
			c.httpCli = client
		}
	}
}

// WithOpaClienter overrides the Clienter used to call Opa.
// This option takes precedence over WithHTTPClient.
func WithOpaClienter(clienter opa_client.Clienter) Option {
	return func(c *Config) {
		if clienter != nil {
			c.clienter = clienter
		}
	}
}

// WithOpaEvaluator overrides the OpaEvaluator use to
// evaluate authorization against OPA.
func WithOpaEvaluator(opaEvaluator OpaEvaluator) Option {
	return func(c *Config) {
		c.opaEvaluator = opaEvaluator
	}
}

// WithAuthorizer overrides the request/response
// processing of OPA. Multiple authorizers can be passed
func WithAuthorizer(auther ...Authorizer) Option {
	return func(c *Config) {
		c.authorizer = auther
	}
}

// WithDecisionInputHandler supplies optional DecisionInputHandler
// for DefaultAuthorizer to obtain additional input for OPA
// ABAC decision processing.
func WithDecisionInputHandler(decisionHandler DecisionInputHandler) Option {
	return func(c *Config) {
		c.decisionInputHandler = decisionHandler
	}
}

// WithClaimsVerifier overrides default ClaimsVerifier
func WithClaimsVerifier(claimsVerifier ClaimsVerifier) Option {
	return func(c *Config) {
		c.claimsVerifier = claimsVerifier
	}
}

// WithEntitledServices overrides default EntitledServices
func WithEntitledServices(entitledServices ...string) Option {
	return func(c *Config) {
		c.entitledServices = entitledServices
	}
}
