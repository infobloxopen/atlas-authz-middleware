package goapi

import (
	"bytes"
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
)

var (
	ErrForbidden  = status.Errorf(codes.PermissionDenied, "Request forbidden: not authorized")
	ErrUnknown    = status.Errorf(codes.Unknown, "Unknown error")
	ErrInvalidArg = status.Errorf(codes.InvalidArgument, "Invalid argument")
)

func startOPA(config *Config) (*sdk.OPA, error) {
	// TODO configurable via options
	opaLogLevel := logging.Debug
	opaLogger := logging.New()
	opaLogger.SetLevel(opaLogLevel)

	ctx := context.Background()


	cfg, err := os.ReadFile(config.OPAConfigFile.Name())
	if err != nil {
		logrus.Fatal(err)
	}

	return sdk.New(ctx, sdk.Options{Config: bytes.NewReader(cfg), Logger: opaLogger})
}
