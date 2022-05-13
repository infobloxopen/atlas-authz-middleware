package wasm

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultAcctEntitlementsApiPath is default OPA path to fetch acct entitlements
	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"
	DefaultDecisionPath            = "/authz/rbac/validate_v1"
)

type Config struct {
	applicaton string
	// decisionPath is a path of a rule: data.<package-path>.<rule-name>
	decisionPath string
	// opaConfigFile configures OPA
	opaConfigFile        *os.File
	decisionInputHandler DecisionInputHandler
	claimsVerifier       ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
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

// OPAConfigObject defines the top level OPA config to go to json
type OPAConfigObject struct {
	Services             map[string]Service `json:"services,omitempty"`
	Labels               map[string]string  `json:"labels,omitempty"`
	Bundles              map[string]Bundle  `json:"bundles,omitempty"`
	DecisionLogs         *DecisionLogs      `json:"decision_logs,omitempty"`
	DefaultDecision      string             `json:"default_decision,omitempty"`
	PersistenceDirectory string             `json:"persistence_directory,omitempty"`
}

// OPAConfigValues ...
type OPAConfigValues struct {
	address             string
	resource            string
	defaultDecisionPath string
	token               string
	persistBundle       bool
	// persistDir is a directory to store OPA state, for example bundles
	persistDir string
}

// createOPAConfigFile ...
// https://www.openpolicyagent.org/docs/latest/configuration/
// https://github.com/michaelboulton/opa-test/tree/a3cb64f6d8dbaa633e2581e853222025d26c6014/pkg/opa
func createOPAConfigFile(val OPAConfigValues, log *logrus.Logger) *os.File {
	config := OPAConfigObject{
		Services: map[string]Service{
			"authz": {
				Name: "authz",
				URL:  val.address,
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
				Resource: val.resource,
				Persist:  val.persistBundle,
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
		DefaultDecision:      val.defaultDecisionPath,
		PersistenceDirectory: val.persistDir,
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

	file, err := ioutil.TempFile("", "*.yaml")
	if err != nil {
		log.Fatal(err)
	}

	_, err = file.Write(asYAML)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("OPA config file name: %s", file.Name())
	return file
}
