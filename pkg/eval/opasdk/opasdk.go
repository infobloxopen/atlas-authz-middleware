package opasdk

import (
	"context"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/plugins/bundle"
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

	// options
	cfg := config.opaConfigBuf
	log := opaLogger
	ctx := context.Background()

	opa, err := sdk.New(ctx, sdk.Options{Config: cfg, Plugins: nil, Logger: log})
	if err != nil {
		return nil, fmt.Errorf("OPA initialization error: %v", err)
	}

	switch p := opa.Plugin("bundle").(type) {
	case *bundle.Plugin:
		go func() {
			config.logger.Infof("Starting bundle reload every %s", config.bundleReloadInterval)
			for range time.Tick(config.bundleReloadInterval) {
				if err := p.Trigger(ctx); err != nil {
					config.logger.Panicf("Reload bundle error: %v", err)
				}
			}
		}()
	default:
		return nil, fmt.Errorf("failed to cast to *bundle.Plugin, received type: %T", p)
	}

	return opa, nil
}
