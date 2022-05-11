package goapi

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// UnaryServerInterceptor returns a new unary client interceptor
// that optionally logs the execution of external gRPC calls.
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opthub := &OptHub{}
	for _, opt := range opts {
		opt(opthub)
	}

	if opthub.Authorizers == nil {
		logrus.Info("No outside authorizers are given, using in-package authorizer")
		a, err := NewAutorizer(opthub.Config)
		if err != nil {
			logrus.Fatal(err)
		}
		opthub.Authorizers = []Authorizer{a}
	}

	return func(ctx context.Context, grpcReq interface{}, info *grpc.UnaryServerInfo, grpcUnaryHandler grpc.UnaryHandler) (interface{}, error) {
		logger := ctxlogrus.Extract(ctx)

		for _, a := range opthub.Authorizers {
			input := map[string]interface{}{
				"message": "TODO",
			}
			logger.WithField("authorizer", a).Debugf("input: %+v", input)
			res, err := a.Authorize(ctx, input)
			if err != nil {
				logger.WithError(err).WithField("authorizer", a).Error("unable_authorize")
			}
			logger.WithField("authorizer", a).Debugf("authorization result: %+v", res)
		}

		return grpcUnaryHandler(ctx, grpcReq)
	}
}
