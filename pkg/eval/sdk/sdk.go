package sdk

import (
	"context"
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

	return sdk.New(context.Background(), sdk.Options{Config: config.opaConfigBuf, Logger: opaLogger})
}
