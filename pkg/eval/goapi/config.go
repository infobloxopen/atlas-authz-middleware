package goapi

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultAcctEntitlementsApiPath is default OPA path to fetch acct entitlements
	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"
	DefaultDecisionPath = "/authz/rbac/validate_v1"
)

type Config struct {
	Applicaton string
	// DecisionPath is a path of a rule: data.<package-path>.<rule-name>
	DecisionPath  string
	OPAConfigFile *os.File

	decisionInputHandler DecisionInputHandler
	claimsVerifier       ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string

}

// Service defines a service
// services:
//  - name: acmecorp
//    url: https://example.com/service/v1
//    credentials:
//      bearer:
//        token: "bGFza2RqZmxha3NkamZsa2Fqc2Rsa2ZqYWtsc2RqZmtramRmYWxkc2tm"
//
type Service struct {
	Name        string                 `json:"name,omitempty"`
	URL         string                 `json:"url,omitempty"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
}

// Bundle defines a bundle
// bundles:
//  authz:
//    service: acmecorp
//    resource: somedir/bundle.tar.gz
//    persist: true
//    polling:
//      min_delay_seconds: 10
//      max_delay_seconds: 20
//    signing:
//      keyid: my_global_key
//      scope: read
type Bundle struct {
	Service  string   `json:"service,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Persist  bool     `json:"persist,omitempty"`
	Polling  *Polling `json:"polling,omitempty"`
	Signing  *Signing `json:"signing,omitempty"`
}
type Polling struct {
	MinDelaySeconds int `json:"min_delay_seconds,omitempty"`
	MaxDelaySeconds int `json:"max_delay_seconds,omitempty"`
}
type Signing struct {
	Keyid string `json:"keyid,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type DecisionLogs struct {
	Console bool `json:"console,omitempty"`
}

// OPAConfig defines the top level OPA config to go to json
type OPAConfig struct {
	//Services     []Service         `json:"services,omitempty"`
	Services     map[string]Service `json:"services,omitempty"`
	Bundles      map[string]Bundle  `json:"bundles,omitempty"`
	DecisionLogs DecisionLogs       `json:"decision_logs,omitempty"`
}

// createOPAConfigFile ...
// https://www.openpolicyagent.org/docs/latest/configuration/
// https://github.com/michaelboulton/opa-test/tree/a3cb64f6d8dbaa633e2581e853222025d26c6014/pkg/opa
func createOPAConfigFile(addr string, resource string, token string) *os.File {
	config := OPAConfig{
		Services: map[string]Service{
			"authz": {
				Name: "authz",
				URL:  addr,
				//Credentials: map[string]interface{}{
				//	"bearer": map[string]string{
				//		"token": token,
				//	},
				//},
			},
		},
		Bundles: map[string]Bundle{
			"authz": {
				Service:  "authz",
				Resource: resource,
				//Persist:  false,
				//Polling:  nil,
				//Signing:  nil,
			},
		},
		DecisionLogs: DecisionLogs{
			Console: true,
		},
	}

	asJson, err := json.Marshal(config)
	if err != nil {
		logrus.Fatal(err)
	}
	intermediary := map[string]interface{}{}
	err = yaml.Unmarshal(asJson, &intermediary)
	if err != nil {
		logrus.Fatal(err)
	}

	fmt.Println(string(asJson))

	asYaml, err := yaml.Marshal(intermediary)
	if err != nil {
		logrus.Fatal(err)
	}

	fmt.Println(string(asYaml))

	file, err := ioutil.TempFile("", "*.yaml")
	if err != nil {
		logrus.Fatal(err)
	}

	_, err = file.Write(asYaml)
	if err != nil {
		logrus.Fatal(err)
	}

	return file
}
