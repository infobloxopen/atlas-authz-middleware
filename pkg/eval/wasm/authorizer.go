package wasm

import (
	"context"
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
	Authorize(ctx context.Context, input *InputPayload) (interface{}, error)
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
func (a *autorizer) Authorize(ctx context.Context, input *InputPayload) (interface{}, error) {
	log := ctxlogrus.Extract(ctx).WithFields(logrus.Fields{
		"application": a.config.applicaton,
	})

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
	log.WithFields(logrus.Fields{
		"result_id": res.ID,
	}).Debugf("OPA_result: %v", res.Result)

	return res.Result, nil
}
