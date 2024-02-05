package authorizer

import (
	"net/http"
	"slices"
	"strings"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/sirupsen/logrus"
)

// DefaultModifyConfig represents the default configuration for modifying endpoints.
type DefaultModifyConfig struct {
	SegmentsNeeded int    // Number of segments needed in the modified endpoint.
	SegmentStart   int    // Index of the segment to start modification from, value should be >=1.
	Prefix         string // Prefix to add to the modified endpoint.
}

// EndpointModifier represents a configuration for modifying endpoints.
type EndpointModifier struct {
	DefaultModifyConfig // Default configuration for modifying endpoints.
	Modify              func(string) string // Function to modify the endpoint.
}

// defaultModify modifies the endpoint using the default configuration.
func (e *EndpointModifier) defaultModify(endpoint string) string {
	segments := strings.Split(endpoint, "/")
	verb := segments[0]
	shortSegments := segments[e.SegmentStart : e.SegmentStart+e.SegmentsNeeded]
	if len(e.Prefix) > 0 {
		shortSegments = slices.Insert(shortSegments, 0, e.Prefix)
	}
	shortSegments = slices.Insert(shortSegments, 0, verb)
	return strings.Join(shortSegments, "/")
}

// getModifiedEndpoint returns the modified endpoint based on the configuration.
func (e *EndpointModifier) getModifiedEndpoint(endpoint string) string {
	if e.Modify == nil {
		return e.defaultModify(endpoint)
	}
	return e.Modify(endpoint)
}

// Config represents the configuration options for the HTTP authorizer.
type Config struct {
	httpCli             *http.Client          // HTTP client for making requests.
	address             string                // Address to OPA.
	clienter            opa_client.Clienter   // OPA clienter for calling OPA.
	opaEvaluator        OpaEvaluator          // OPA evaluator for authorization evaluation.
	authorizer          []HTTPAuthorizer      // HTTP authorizers for request/response processing.
	decisionInputHandler DecisionInputHandler // Decision input handler for obtaining additional input for OPA decision processing.
	claimsVerifier      ClaimsVerifier        // Claims verifier for verifying claims.
	entitledServices    []string              // Entitled services.
	acctEntitlementsApi string                // Account entitlements API path.
	endpointModifier    *EndpointModifier     // Endpoint modifier for modifying endpoints.
}

// GetAuthorizer returns the HTTP authorizers configured in the Config.
func (c Config) GetAuthorizer() []HTTPAuthorizer {
	return c.authorizer
}

// NewDefaultConfig returns a new default Config for the HTTP authorizer.
func NewDefaultConfig(application string, opts ...Option) *Config {
	cfg := &Config{
		address: opa_client.DefaultAddress,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	opts = append([]Option{WithOpaClienter(opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli)))}, opts...)

	authorizer := NewHttpAuthorizer(application, opts...)

	if cfg.authorizer == nil {
		logrus.Info("authorizers empty, using default authorizer")
		cfg.authorizer = []HTTPAuthorizer{authorizer}
	}

	return cfg
}

// Option represents a configuration option for the Config.
type Option func(c *Config)

// WithAddress sets the address to OPA.
func WithAddress(address string) Option {
	return func(c *Config) {
		c.address = address
	}
}

// WithHTTPClient sets the HTTP client used to call OPA.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		if client != nil {
			c.httpCli = client
		}
	}
}

// WithOpaClienter sets the OPA clienter used to call OPA.
func WithOpaClienter(clienter opa_client.Clienter) Option {
	return func(c *Config) {
		if clienter != nil {
			c.clienter = clienter
		}
	}
}

// WithOpaEvaluator sets the OPA evaluator used for authorization evaluation.
func WithOpaEvaluator(opaEvaluator OpaEvaluator) Option {
	return func(c *Config) {
		c.opaEvaluator = opaEvaluator
	}
}

// WithAuthorizer sets the HTTP authorizers for request/response processing.
func WithAuthorizer(auther ...HTTPAuthorizer) Option {
	return func(c *Config) {
		c.authorizer = auther
	}
}

// WithDecisionInputHandler sets the decision input handler for obtaining additional input for OPA decision processing.
func WithDecisionInputHandler(decisionHandler DecisionInputHandler) Option {
	return func(c *Config) {
		c.decisionInputHandler = decisionHandler
	}
}

// WithClaimsVerifier sets the claims verifier for verifying claims.
func WithClaimsVerifier(claimsVerifier ClaimsVerifier) Option {
	return func(c *Config) {
		c.claimsVerifier = claimsVerifier
	}
}

// WithEntitledServices sets the entitled services.
func WithEntitledServices(entitledServices ...string) Option {
	return func(c *Config) {
		c.entitledServices = entitledServices
	}
}

// WithAcctEntitlementsApiPath sets the account entitlements API path.
func WithAcctEntitlementsApiPath(acctEntitlementsApi string) Option {
	return func(c *Config) {
		c.acctEntitlementsApi = acctEntitlementsApi
	}
}

// WithEndpointModifier sets the endpoint modifier for modifying endpoints.
func WithEndpointModifier(modifier *EndpointModifier) Option {
	return func(c *Config) {
		c.endpointModifier = modifier
	}
}
