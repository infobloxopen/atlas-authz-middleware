package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infobloxopen/atlas-app-toolkit/requestid"
	"github.com/infobloxopen/atlas-authz-middleware/common"
	az "github.com/infobloxopen/atlas-authz-middleware/common/authorizer"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/common/opautil"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	atlas_claims "github.com/infobloxopen/atlas-claims"
)

// Override to set your servicename
var (
	SERVICENAME = "opa"
)

var (
	ErrForbidden  = status.Errorf(codes.PermissionDenied, "Request forbidden: not authorized")
	ErrUnknown    = status.Errorf(codes.Unknown, "Unknown error")
	ErrInvalidArg = status.Errorf(codes.InvalidArgument, "Invalid argument")
)

var defDecisionInputer = new(az.DefaultDecisionInputer)

type AuthorizeFn func(ctx context.Context, fullMethodName string, grpcReq interface{}, opaEvaluator az.OpaEvaluator) (bool, context.Context, error)

func (a AuthorizeFn) OpaQuery(opaReq, opaResp interface{}) error {
	return nil
}

func (a AuthorizeFn) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator az.OpaEvaluator) (bool, context.Context, error) {
	return a(ctx, fullMethod, grpcReq, opaEvaluator)
}

func NewDefaultAuthorizer(application string, opts ...Option) *DefaultAuthorizer {
	cfg := &Config{
		address:              opa_client.DefaultAddress,
		decisionInputHandler: defDecisionInputer,
		claimsVerifier:       commonClaim.UnverifiedClaimFromBearers,
		acctEntitlementsApi:  common.DefaultAcctEntitlementsApiPath,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	//log.Debugf("cfg=%+v", *cfg)

	clienter := cfg.clienter
	if clienter == nil {
		clienter = opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli))
	}

	a := DefaultAuthorizer{
		clienter:             clienter,
		opaEvaluator:         cfg.opaEvaluator,
		application:          application,
		decisionInputHandler: cfg.decisionInputHandler,
		claimsVerifier:       cfg.claimsVerifier,
		entitledServices:     cfg.entitledServices,
		acctEntitlementsApi:  cfg.acctEntitlementsApi,
	}
	return &a
}

type DefaultAuthorizer struct {
	application          string
	clienter             opa_client.Clienter
	opaEvaluator         az.OpaEvaluator
	decisionInputHandler az.DecisionInputHandler
	claimsVerifier       az.ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
}

type Config struct {
	httpCli *http.Client
	// address to opa
	address string

	clienter             opa_client.Clienter
	opaEvaluator         az.OpaEvaluator
	authorizer           []az.Authorizer
	decisionInputHandler az.DecisionInputHandler
	claimsVerifier       az.ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
}

//	FullMethod is the full RPC method string, i.e., /package.service/method.
//
// e.g. fullmethod:  /service.TagService/ListRetiredTags PARGs endpoint: TagService.ListRetiredTags
func parseEndpoint(fullMethod string) string {
	byPackage := strings.Split(fullMethod, ".")
	endpoint := byPackage[len(byPackage)-1]
	return strings.Replace(endpoint, "/", ".", -1)
}

func (a DefaultAuthorizer) String() string {
	return fmt.Sprintf(`grpc_opa_middleware.DefaultAuthorizer{application:"%s" clienter:%s decisionInputHandler:%s}`,
		a.application, a.clienter, a.decisionInputHandler)
}

func (a *DefaultAuthorizer) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator az.OpaEvaluator) (bool, context.Context, error) {

	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	// This fetches auth data from auth headers in metadata from context:
	// bearer = data from "authorization bearer" metadata header
	// newBearer = data from "set-authorization bearer" metadata header
	bearer, newBearer := atlas_claims.AuthBearersFromCtx(ctx)

	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = commonClaim.UnverifiedClaimFromBearers
	}

	rawJWT, errs := claimsVerifier([]string{bearer}, []string{newBearer})
	if len(errs) > 0 {
		return false, ctx, fmt.Errorf("%q", errs)
	}

	reqID, ok := requestid.FromContext(ctx)
	if !ok {
		reqID = "no-request-uuid"
	}

	opaReq := opautil.Payload{
		Endpoint:    parseEndpoint(fullMethod),
		FullMethod:  fullMethod,
		Application: a.application,
		// FIXME: implement atlas_claims.AuthBearersFromCtx
		JWT:              opautil.RedactJWT(rawJWT),
		RequestID:        reqID,
		EntitledServices: a.entitledServices,
	}

	decisionInput, err := a.decisionInputHandler.GetDecisionInput(ctx, fullMethod, grpcReq)
	if decisionInput == nil || err != nil {
		logger.WithFields(log.Fields{
			"fullMethod": fullMethod,
		}).WithError(err).Error("get_decision_input")
		return false, ctx, ErrInvalidArg
	}
	//logger.Debugf("decisionInput=%+v", *decisionInput)
	opaReq.DecisionInput = *decisionInput

	opaReqJSON, err := json.Marshal(opaReq)
	if err != nil {
		logger.WithFields(log.Fields{
			"opaReq": opaReq,
		}).WithError(err).Error("opa_request_json_marshal")
		return false, ctx, ErrInvalidArg
	}

	now := time.Now()
	obfuscatedOpaReq := opautil.ShortenPayloadForDebug(opaReq)
	logger.WithFields(log.Fields{
		"opaReq": obfuscatedOpaReq,
		//"opaReqJSON": string(opaReqJSON),
	}).Debug("opa_authorization_request")

	// To enable tracing, the context must have a tracer attached
	// to it. See the tracing documentation on how to do this.
	ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, fullMethod))
	{
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("in", string(opaReqJSON)),
		}, "in")
	}
	// FIXME: perhaps only inject these fields if this is the default handler

	// If DecisionDocument is empty, the default OPA-configured decision document is queried.
	// In this case, the input payload MUST NOT be encapsulated inside "input".
	// Otherwise for any other non-empty DecisionDocument, even if it's the same as the default
	// OPA-configured decision document, the input payload MUST be encapsulated inside "input".
	// (See comments in testdata/mock_system_main.rego)
	var opaInput interface{}
	opaInput = opaReq
	if len(decisionInput.DecisionDocument) > 0 {
		opaInput = opautil.OPARequest{Input: &opaReq}
	}

	var opaResp opautil.OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, opaInput, &opaResp)
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
		logger.WithFields(log.Fields{
			"opaResp": opaResp,
			"elapsed": time.Since(now),
		}).Debug("authorization_result")
	}()
	if err != nil {
		return false, ctx, err
	}

	// When we POST query OPA without url path, it returns results NOT encapsulated inside "result":
	//   {"allow": true, ...}
	// When we POST query OPA with explicit decision document, it returns results encapsulated inside "result":
	//   {"result":{"allow": true, ...}}
	// (See comments in testdata/mock_system_main.rego)
	// If the JSON result document is nested within "result" wrapper map,
	// we extract the nested JSON document and throw away the "result" wrapper map.
	nestedResultVal, resultIsNested := opaResp["result"]
	if resultIsNested {
		nestedResultMap, ok := nestedResultVal.(map[string]interface{})
		if ok {
			opaResp = opautil.OPAResponse{}
			for k, v := range nestedResultMap {
				opaResp[k] = v
			}
		}
	}

	// Log non-err opa responses
	{
		raw, _ := json.Marshal(opaResp)
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("out", string(raw)),
		}, "out")
	}

	// adding raw entitled_features data to context if present
	ctx = opaResp.AddRawEntitledFeatures(ctx)

	// adding obligations data to context if present
	ctx, err = opautil.AddObligations(ctx, opaResp)
	if err != nil {
		logger.WithField("opaResp", fmt.Sprintf("%#v", opaResp)).WithError(err).Error("parse_obligations_error")
	}

	if !opaResp.Allow() {
		return false, ctx, ErrForbidden
	}

	return true, ctx, nil
}

func (a *DefaultAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	if a.opaEvaluator != nil {
		return a.opaEvaluator(ctx, decisionDocument, opaReq, opaResp)
	}

	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, opaReq, opaResp)
	// TODO: allow overriding logger
	if err != nil {
		grpcErr := opa_client.GRPCError(err)
		logger.WithError(grpcErr).Error("opa_policy_engine_request_error")
		return az.OpaqueError(grpcErr)
	}

	logger.WithField("opaResp", opaResp).Debug("opa_policy_engine_response")
	return err
}

// AffirmAuthorization makes an authz request to sidecar-OPA.
// If authorization is permitted, error returned is nil,
// and a new context is returned, possibly containing obligations.
// Caller must further evaluate obligations if required.
func (a *DefaultAuthorizer) AffirmAuthorization(ctx context.Context, fullMethod string, grpcReq interface{}) (context.Context, error) {
	logger := ctxlogrus.Extract(ctx)
	var (
		ok     bool
		newCtx context.Context
		err    error
	)

	ok, newCtx, err = a.Evaluate(ctx, fullMethod, grpcReq, a.OpaQuery)
	if err != nil {
		logger.WithError(err).WithField("authorizer", a).Error("unable_authorize")
		return nil, err
	}

	if !ok {
		err = opa_client.ErrUndefined
		logger.WithError(err).Error("policy engine returned undefined response")
		return nil, err
	}

	return newCtx, nil
}

var (
	errUnavailable = status.Error(codes.Unavailable, `Post http://localhost:8181/: dial tcp: connection refused`)
)
