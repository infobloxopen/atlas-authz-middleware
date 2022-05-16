package sdk

import (
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

var (
	ErrForbidden  = status.Errorf(codes.PermissionDenied, "Request forbidden: not authorized")
	ErrUnknown    = status.Errorf(codes.Unknown, "Unknown error")
	ErrInvalidArg = status.Errorf(codes.InvalidArgument, "Invalid argument")
)

// Authorizer interface ...
type Authorizer interface {
	Authorize(ctx context.Context, input *InputPayload) (*sdk.DecisionResult, error)
}

type autorizer struct {
	engine *sdk.OPA
	config *Config
}

func NewAutorizer(config *Config) (*autorizer, error) {
	config.opaConfigBuf = createOPAConfigBuf(&config.opaConfig, config.logger)
	opa, err := startOPA(config)

	if err != nil {
		logrus.Fatal(err)
	}
	return &autorizer{
		engine: opa,
		config: config,
	}, nil

	// TODO figure out if we need stopping the opa
	// defer opa.Stop(ctx)
}

// Authorize ...
func (a *autorizer) Authorize(ctx context.Context, input *InputPayload) (*sdk.DecisionResult, error) {
	log := ctxlogrus.Extract(ctx)

	document := input.DecisionInput.DecisionDocument
	log.Debugf("input_decision_document: %s", document)

	// Wrap input ...
	type Wrap struct {
		// OPA expects field called "input" to contain input payload
		Input interface{} `json:"input"`
	}

	var in interface{}
	// If DecisionDocument is empty, the default OPA-configured decision document is queried.
	// In this case, the input payload MUST NOT be encapsulated inside "input".
	// Otherwise for any other non-empty DecisionDocument, even if it's the same as the default
	// OPA-configured decision document, the input payload MUST be encapsulated inside "input".
	// (See comments in testdata/mock_system_main.rego)
	if len(document) == 0 {
		in = input
	} else {
		in = Wrap{Input: input}
	}
	log.Debugf("OPA_input: %+v", in)

	res, err := a.engine.Decision(ctx, sdk.DecisionOptions{
		Now:   time.Now(),
		Path:  a.config.decisionPath,
		Input: in,
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"request_opa_payload": in,
		}).WithError(err).Errorf("OPA_decision_error: %v", err)
		return nil, ErrUnknown
	}
	return res, nil
}

func dumpDecisionResult(log *logrus.Logger, result sdk.DecisionResult, inYAML bool) {
	asJSON, err := json.Marshal(result)
	if err != nil {
		log.Errorf("JSON marshal error: %v", err)
		log.Printf("Decision result: %+v", result)
		return
	}

	if inYAML {
		m := map[string]interface{}{}
		if err := yaml.Unmarshal(asJSON, &m); err != nil {
			log.Errorf("YAML unmarshal error: %v", err)
			log.Printf("Decision result JSON: %+v", asJSON)
			return
		}

		asYAML, err := yaml.Marshal(m)
		if err != nil {
			log.Errorf("YAML marshal error: %v", err)
			log.Printf("Decision result JSON: %+v", asJSON)
			return
		}
		log.Printf("Decision result YAML: \n%s", asYAML)
		return
	}

	log.Printf("Decision result JSON: \n%s", asJSON)
}
