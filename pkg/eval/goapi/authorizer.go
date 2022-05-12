package goapi

import (
	"context"
	"encoding/json"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"time"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

// Authorizer interface ...
type Authorizer interface {
	Authorize(ctx context.Context, cfg *Config, input *InputPayload) (interface{}, error)
}

type autorizer struct {
	engine *sdk.OPA
	config *Config
}

func NewAutorizer(config *Config) (*autorizer, error) {
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
func (a *autorizer) Authorize(ctx context.Context, cfg *Config, input *InputPayload) (interface{}, error) {
	log := ctxlogrus.Extract(ctx).WithFields(logrus.Fields{
		"application": cfg.Applicaton,
	})

	// InputWrap ...
	type Wrap struct {
		// OPA expects field called "input" to contain input payload
		Input interface{} `json:"input"`
	}

	document := input.DecisionInput.DecisionDocument
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

	js, err := json.Marshal(in)
	if err != nil {
		log.WithFields(logrus.Fields{
			"request_opa_payload": in,
		}).WithError(err).Errorf("JSON_marshal_error: %v", err)
		return nil, err
	}

	res, err := a.engine.Decision(ctx, sdk.DecisionOptions{
		Now:   time.Now(),
		Path:  a.config.DecisionPath,
		Input: js,
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"request_opa_payload": in,
		}).WithError(err).Errorf("OPA_decision_error: %v", err)
		return nil, ErrUnknown
	}
	log.WithFields(logrus.Fields{
		"result_id": res.ID,
	}).Debugf("OPA_result: %v", res.Result)

	return res.Result, nil
}
