package wasm

import "github.com/sirupsen/logrus"

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

// WithDecisionPath ...
func WithDecisionPath(path string) Option {
	return func(c *OptHub) {
		c.decisionPath = path
	}
}

// WithBundleResourcePath accepts an absolute path with the leading
// slash to a bundle file that the opa should use as data. If not
// configured, "/bundle/bundle.tar.gz" is used as the default.
// Polling bundles from remote HTTP server is not supported.
func WithBundleResourcePath(path string) Option {
	return func(c *OptHub) {
		if path != "" {
			path = "file://" + path
		}
		c.bundleResourcePath = path
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

// WithLogger sets the logrus logger from the calling application
// that has one of logrus logging levels
// (Trace, Debug, Info, Warning, Error, Fatal, Panic).
// OPA SDK has its own set of logging levels (Debug, Info,
// Warn, Error). OPA logger log level is also configured by
// this option to the nearest counterpart:
//
// - Panic, Fatal, Error = Error
//
// - Warn = Warn
//
// - Info = Info
//
// - Debug, Trace = Debug
func WithLogger(logger *logrus.Logger) Option {
	return func(c *OptHub) {
		c.logger = logger
	}
}
