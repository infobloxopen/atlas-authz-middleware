package wasm

import (
	"bytes"
	"context"
	"os"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

func startOPA(config *Config) (*sdk.OPA, error) {
	opaLogLevel := logging.Info

	switch config.logger.GetLevel() {
	case logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel:
		opaLogLevel = logging.Error
	case logrus.WarnLevel:
		opaLogLevel = logging.Warn
	case logrus.InfoLevel:
		opaLogLevel = logging.Info
	case logrus.DebugLevel, logrus.TraceLevel:
		opaLogLevel = logging.Debug
	}

	opaLogger := logging.New()
	opaLogger.SetLevel(opaLogLevel)

	ctx := context.Background()

	cfg, err := os.ReadFile(config.opaConfigFile.Name())
	if err != nil {
		logrus.Fatal(err)
	}

	return sdk.New(ctx, sdk.Options{Config: bytes.NewReader(cfg), Logger: opaLogger})
}
