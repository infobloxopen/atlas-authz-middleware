package wasm

import (
	"bytes"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultAcctEntitlementsApiPath is default OPA path to fetch acct entitlements
	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"
	DefaultDecisionPath            = "/authz/rbac/validate_v1"
	DefaultBundleResourcePath      = "/bundle/bundle.tar.gz"
	DefaultLoggingLevel            = logrus.InfoLevel
)

type Config struct {
	opaConfig
	applicaton           string
	decisionInputHandler DecisionInputHandler
	claimsVerifier       ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
	logger               *logrus.Logger
}

// opaConfig ...
type opaConfig struct {
	// decisionPath is a path of a rule: data.<package-path>.<rule-name>
	decisionPath        string
	defaultDecisionPath string
	// bundleResourcePath is an absolute path to a bundle file for
	// the middleware to fetch it from. Using remote HTTP server is not supported.
	// If the path is empty, "file:///bundle/bundle.tar.gz" is used as the default.
	bundleResourcePath string
	serviceURL         string
	serviceCredToken   string
	persistBundle      bool
	// persistDir is a directory to store OPA state, for example bundles
	persistDir string
	opaConfigBuf  *bytes.Buffer
}

type Service struct {
	Name        string                 `json:"name,omitempty"`
	URL         string                 `json:"url,omitempty"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
}

type Bundle struct {
	Service  string   `json:"service,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Persist  bool     `json:"persist,omitempty"`
	Polling  *Polling `json:"polling,omitempty"`
	Signing  *Signing `json:"signing,omitempty"`
}

type Polling struct {
	MinDelaySeconds    int `json:"min_delay_seconds,omitempty"`
	MaxDelaySeconds    int `json:"max_delay_seconds,omitempty"`
	LongPollTimeoutSec int `json:"long_polling_timeout_seconds,omitempty"`
}

type Reporting struct {
	MinDelaySeconds int `json:"min_delay_seconds,omitempty"`
	MaxDelaySeconds int `json:"max_delay_seconds,omitempty"`
}
type Signing struct {
	Keyid string `json:"keyid,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type DecisionLogs struct {
	Service   string     `json:"service,omitempty"`
	Console   bool       `json:"console,omitempty"`
	Reporting *Reporting `json:"reporting,omitempty"`
}

// OPAConfig defines the top level OPA config to go to json
type OPAConfig struct {
	Services             map[string]Service `json:"services,omitempty"`
	Labels               map[string]string  `json:"labels,omitempty"`
	Bundles              map[string]Bundle  `json:"bundles,omitempty"`
	DecisionLogs         *DecisionLogs      `json:"decision_logs,omitempty"`
	DefaultDecision      string             `json:"default_decision,omitempty"`
	PersistenceDirectory string             `json:"persistence_directory,omitempty"`
}

// createOPAConfigBuf ...
// https://www.openpolicyagent.org/docs/latest/configuration/
// https://github.com/michaelboulton/opa-test/tree/a3cb64f6d8dbaa633e2581e853222025d26c6014/pkg/opa
func createOPAConfigBuf(cfg *opaConfig, log *logrus.Logger) *bytes.Buffer {
	config := OPAConfig{
		Services: map[string]Service{
			"authz": {
				Name: "authz",
				URL:  cfg.serviceURL,
				//Credentials: map[string]interface{}{
				//	"bearer": map[string]string{
				//		"token": val.token,
				//	},
				//},
			},
		},
		Bundles: map[string]Bundle{
			"authz": {
				Service:  "authz",
				Resource: cfg.bundleResourcePath,
				Persist:  cfg.persistBundle,
				Polling: &Polling{
					MinDelaySeconds:    60,
					MaxDelaySeconds:    120,
					LongPollTimeoutSec: 10,
				},
				Signing: nil,
			},
		},
		DecisionLogs: &DecisionLogs{
			Service: "authz",
			Console: true,
			Reporting: &Reporting{
				MinDelaySeconds: 300,
				MaxDelaySeconds: 600,
			},
		},
		DefaultDecision:      cfg.defaultDecisionPath,
		PersistenceDirectory: cfg.persistDir,
	}

	asJSON, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("OPA config JSON: \n%s", asJSON)

	intermediary := map[string]interface{}{}
	if err := yaml.Unmarshal(asJSON, &intermediary); err != nil {
		log.Fatal(err)
	}

	asYAML, err := yaml.Marshal(intermediary)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("OPA config YAML: \n%s", asYAML)

	var buf bytes.Buffer
	buf.Write(asYAML)

	return &buf
}
