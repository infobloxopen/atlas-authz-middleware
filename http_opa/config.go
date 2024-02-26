package httpopa

import (
	"net/http"
	"slices"
	"strings"

	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/sirupsen/logrus"
)

type DefaultModifyConfig struct {
	SegmentsNeeded int
	SegmentStart   int
	Prefix         string
}

type EndpointModifier struct {
	DefaultModifyConfig
	Modify func(string) string
}

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

func (e *EndpointModifier) getModifiedEndpoint(endpoint string) string {
	if e.Modify == nil {
		return e.defaultModify(endpoint)
	}
	return e.Modify(endpoint)
}

type Config struct {
	httpCli *http.Client
	// address to opa
	address string

	clienter                opa_client.Clienter
	opaEvaluator            az.OpaEvaluator
	authorizer              []az.Authorizer
	decisionInputHandler    az.DecisionInputHandler
	claimsVerifier          az.ClaimsVerifier
	entitledServices        []string
	acctEntitlementsApi     string
	currUserCompartmentsApi string
	endpointModifier        *EndpointModifier
}

func (c Config) GetAuthorizer() []az.Authorizer {
	return c.authorizer
}

// NewDefaultConfig returns a new default Config for Http Authorizer.
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
		cfg.authorizer = []az.Authorizer{authorizer}
	}

	return cfg
}

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
func WithOpaEvaluator(opaEvaluator az.OpaEvaluator) Option {
	return func(c *Config) {
		c.opaEvaluator = opaEvaluator
	}
}

// WithAuthorizer overrides the request/response
// processing of OPA. Multiple authorizers can be passed
func WithAuthorizer(auther ...az.Authorizer) Option {
	return func(c *Config) {
		c.authorizer = auther
	}
}

// WithDecisionInputHandler supplies optional DecisionInputHandler
// for DefaultAuthorizer to obtain additional input for OPA
// ABAC decision processing.
func WithDecisionInputHandler(decisionHandler az.DecisionInputHandler) Option {
	return func(c *Config) {
		c.decisionInputHandler = decisionHandler
	}
}

// WithClaimsVerifier overrides default ClaimsVerifier
func WithClaimsVerifier(claimsVerifier az.ClaimsVerifier) Option {
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

// WithAcctEntitlementsApiPath overrides default AcctEntitlementsApiPath
func WithAcctEntitlementsApiPath(acctEntitlementsApi string) Option {
	return func(c *Config) {
		c.acctEntitlementsApi = acctEntitlementsApi
	}
}

// WithCurrentUserCompartmentsPath overrides default CurrentUserCompartmentsApiPath
func WithCurrentUserCompartmentsPath(currUserCompartmentsApi string) Option {
	return func(c *Config) {
		c.currUserCompartmentsApi = currUserCompartmentsApi
	}
}

// WithAcctSegmentsNeeded overrides default 0
func WithEndpointModifier(modifier *EndpointModifier) Option {
	return func(c *Config) {
		c.endpointModifier = modifier
	}
}
