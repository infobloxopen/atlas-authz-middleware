package wasm

import (
	"context"
	"encoding/json"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"

	"github.com/infobloxopen/atlas-authz-middleware/utils"
)

// UnaryServerInterceptor returns a new unary client interceptor
// that optionally logs the execution of external gRPC calls.
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opthub := &OptHub{}
	// defaults
	opthub.applicaton = "unknown"
	opthub.decisionInputHandler = new(DefaultDecisionInputer)
	opthub.claimsVerifier = utils.UnverifiedClaimFromBearers
	opthub.entitledServices = nil
	opthub.acctEntitlementsApi = DefaultAcctEntitlementsApiPath
	opthub.bundleResourcePath = DefaultBundleResourcePath
	opthub.defaultDecisionPath = DefaultDecisionPath
	opthub.decisionPath = DefaultDecisionPath
	opthub.logger = logrus.New()
	opthub.logger.SetLevel(DefaultLoggingLevel)

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

	dumpOptConfig(opthub.logger, opthub, false)
	verifyOptConfig(opthub)

	return func(ctx context.Context, grpcReq interface{}, info *grpc.UnaryServerInfo, grpcUnaryHandler grpc.UnaryHandler) (interface{}, error) {
		logger := ctxlogrus.Extract(ctx)

		var err error
		for _, a := range opthub.Authorizers {
			logger = logger.WithField("authorizer", a).
				WithField("application", opthub.applicaton)

			// compose imput/payload to OPA
			var input *InputPayload
			input, err = composeInput(ctx, opthub.Config, info.FullMethod, grpcReq)
			if err != nil {
				logger.WithError(err).Error("unable_compose_input")
				continue
			} else if opthub.Config.logger.GetLevel() >= logrus.DebugLevel {
				dumpInputPayload(opthub.Config.logger, *input, false)
			}

			// enable tracing
			span, at := &trace.Span{}, time.Time{}
			ctx, span, err = startSpan(ctx, logger, input)
			if err != nil {
				dumpInputPayload(opthub.Config.logger, *input, false)
				continue
			}

			// authorize
			var result *sdk.DecisionResult
			result, err = a.Authorize(ctx, input)
			if err != nil {
				logger.WithError(err).Error("unable_authorize")
				endSpan(span, err)
				continue
			} else if opthub.Config.logger.GetLevel() >= logrus.DebugLevel {
				dumpDecisionResult(opthub.Config.logger, *result, false)
			}

			logger.WithFields(logrus.Fields{
				"elapsed": time.Since(at),
			}).Debug("authorization_result")

			// trace non-err OPA decision result
			if raw, err := json.Marshal(result); err != nil {
				logger.WithError(err).Errorf("JSON_marshal_error: %v", err)
				dumpDecisionResult(opthub.Config.logger, *result, false)
				endSpan(span, err)
				continue
			} else {
				span.Annotate([]trace.Attribute{
					trace.StringAttribute("out", string(raw)),
				}, "out")
			}

			// parse result
			var resultMap ResultMap
			ctx, resultMap, err = parseResult(ctx, result)
			if err != nil {
				logger.WithError(err).Error("parse_result_error")
				endSpan(span, err)
				continue
			} else if opthub.Config.logger.GetLevel() >= logrus.DebugLevel {
				dumpParsedResult(opthub.Config.logger, resultMap, false)
			}

			// allow or not allow
			if !resultMap.Allow() {
				logger.WithError(err).Error("request_forbidden")
				endSpan(span, err)
				err = ErrForbidden
				continue
			}

			endSpan(span, nil)
			break
		}

		return grpcUnaryHandler(ctx, grpcReq)
	}
}
