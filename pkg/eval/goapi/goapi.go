package goapi

import (
	"bytes"
	"context"
	"os"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

func startOPA() (*sdk.OPA, error) {
	// TODO configurable via options
	opaLogLevel := logging.Debug
	opaLogger := logging.New()
	opaLogger.SetLevel(opaLogLevel)

	ctx := context.Background()

	// TODO configuration
	// https://www.openpolicyagent.org/docs/latest/configuration/
	config, err := os.ReadFile("TODO")
	if err != nil {
		logrus.Fatal(err)
	}

	return sdk.New(ctx, sdk.Options{Config: bytes.NewReader(config), Logger: opaLogger})
}
