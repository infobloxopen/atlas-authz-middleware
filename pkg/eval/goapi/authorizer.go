package goapi

import (
	"context"
	"time"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

// Authorizer interface ...
type Authorizer interface {
	Authorize(context.Context, map[string]interface{}) (interface{}, error)
}

type autorizer struct {
	engine *sdk.OPA
	config *Config
}

func NewAutorizer(config *Config) (*autorizer, error) {
	opa, err := startOPA()
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

// TODO
func (a *autorizer) Authorize(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	return a.engine.Decision(ctx, sdk.DecisionOptions{
		Now:   time.Now(),
		Path:  "/todo",
		Input: input,
	})
}
