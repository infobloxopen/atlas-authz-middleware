package wasm

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

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

func dumpOptConfig(log *logrus.Logger, opthub *OptHub, inYAML bool) {
	opts := map[string]interface{}{
		"loggingLevel":        opthub.logger.GetLevel().String(),
		"applicaton":          opthub.applicaton,
		"decisionPath":        opthub.decisionPath,
		"bundleResourcePath":  opthub.bundleResourcePath,
		"entitledServices":    opthub.entitledServices,
		"acctEntitlementsApi": opthub.acctEntitlementsApi,
	}

	for i, a := range opthub.Authorizers {
		opts["authorizer-"+strconv.Itoa(i)] = fmt.Sprintf("%T", a)
	}

	asJSON, err := json.Marshal(opts)
	if err != nil {
		log.Errorf("JSON marshal error: %v", err)
		log.Printf("Options config: %+v", opts)
		return
	}

	if inYAML {
		m := map[string]interface{}{}
		if err := yaml.Unmarshal(asJSON, &m); err != nil {
			log.Errorf("YAML unmarshal error: %v", err)
			log.Printf("AuthZ middleware options config JSON: %s", string(asJSON))
			return
		}

		asYAML, err := yaml.Marshal(m)
		if err != nil {
			log.Errorf("YAML marshal error: %v", err)
			log.Printf("AuthZ middleware options config JSON: %s", string(asJSON))
			return
		}
		log.Printf("AuthZ middleware options config YAML: \n%s", string(asYAML))
		return
	}
	log.Infof("AuthZ middleware options config JSON: \n%s", string(asJSON))
}

func verifyOptConfig(opthub *OptHub) {
	switch {
	case opthub.applicaton == "unknown":
		opthub.logger.Panic("application should be set")
	}
}
