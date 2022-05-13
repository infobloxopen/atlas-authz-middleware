package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/infobloxopen/atlas-authz-middleware/utils"
	"go.opencensus.io/trace"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Override to set your servicename
var (
	SERVICENAME = "opa"
)

// UnaryServerInterceptor returns a new unary client interceptor
// that optionally logs the execution of external gRPC calls.
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opthub := &OptHub{}
	// defaults
	opthub.decisionInputHandler = new(DefaultDecisionInputer)
	opthub.claimsVerifier = utils.UnverifiedClaimFromBearers
	opthub.entitledServices = nil
	opthub.acctEntitlementsApi = DefaultAcctEntitlementsApiPath
	opthub.decisionPath = DefaultDecisionPath

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
			// compose imput/payload to OPA
			input, err := composeInput(ctx, opthub.Config, info.FullMethod, grpcReq)
			if err != nil {
				logger.WithError(err).Error("unable_compose_input")
				return nil, err
			}

			var result interface{}

			// enable tracing
			now := time.Now()
			js, err := json.Marshal(input)
			if err != nil {
				logger.WithFields(logrus.Fields{
					"request_opa_payload": input,
				}).WithError(err).Errorf("JSON_marshal_error: %v", err)
				return nil, ErrInvalidArg
			}

			// To enable tracing, the context must have a tracer attached
			// to it. See the tracing documentation on how to do this.
			ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, info.FullMethod))
			{
				span.Annotate([]trace.Attribute{
					trace.StringAttribute("in", string(js)),
				}, "in")
			}
			// FIXME: perhaps only inject these fields if this is the default handler

			// Metrics, logging, tracing handler
			defer func() {
				// opencensus Status is based on gRPC status codes
				// https://pkg.go.dev/go.opencensus.io/trace?tab=doc#Status
				// err == nil will return {Code: 200, Message:""}
				span.SetStatus(trace.Status{
					Code:    int32(grpc.Code(err)),
					Message: grpc.ErrorDesc(err),
				})
				span.End()
				logger.WithFields(logrus.Fields{
					"opaResp": result,
					"elapsed": time.Since(now),
				}).Debug("authorization_result")
			}()

			// authorize
			logger.WithField("authorizer", a).Debugf("input: %+v", input)
			result, err = a.Authorize(ctx, input)
			if err != nil {
				logger.WithError(err).WithField("authorizer", a).Error("unable_authorize")
				return nil, ErrUnknown // TODO
			}

			resultMap, err := parseResult(ctx, result)
			if err != nil {
				logger.WithError(err).Error("result_parse_error")
				return nil, ErrUnknown // TODO
			}

			// Log non-err opa responses
			{
				raw, _ := json.Marshal(resultMap)
				span.Annotate([]trace.Attribute{
					trace.StringAttribute("out", string(raw)),
				}, "out")
			}

			if !resultMap.Allow() {
				logger.WithError(err).WithField("authorizer", a).Error("request_forbidden")
				return nil, ErrForbidden
			}
		}

		return grpcUnaryHandler(ctx, grpcReq)
	}
}
