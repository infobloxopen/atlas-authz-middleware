// Package httpopa provides an implementation of the az.Authorizer interface for HTTP-based authorization using OPA (Open Policy Agent).
package httpopa

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/v2/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/opautil"
	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/util"
	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	log "github.com/sirupsen/logrus"
)

// SERVICENAME is the name of the OPA service.
var SERVICENAME = "opa"

// httpAuthorizer is an implementation of the az.Authorizer interface for HTTP-based authorization using OPA.
type httpAuthorizer struct {
	application             string
	clienter                opa_client.Clienter
	opaEvaluator            az.OpaEvaluator
	decisionInputHandler    az.DecisionInputHandler
	claimsVerifier          az.ClaimsVerifier
	entitledServices        []string
	acctEntitlementsApi     string
	currUserCompartmentsApi string
	endpointModifier        *EndpointModifier
}

var defDecisionInputer = new(az.DefaultDecisionInputer)

// NewHttpAuthorizer creates a new instance of httpAuthorizer with the given application name and options.
func NewHttpAuthorizer(application string, opts ...Option) az.Authorizer {
	// Configuration options for the authorizer
	cfg := &Config{
		address:                 opa_client.DefaultAddress,
		decisionInputHandler:    defDecisionInputer,
		claimsVerifier:          commonClaim.UnverifiedClaimFromBearers,
		acctEntitlementsApi:     az.DefaultAcctEntitlementsApiPath,
		currUserCompartmentsApi: az.DefaultCurrentUserCompartmentsPath,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	clienter := cfg.clienter
	if clienter == nil {
		clienter = opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli))
	}

	a := httpAuthorizer{
		clienter:                clienter,
		opaEvaluator:            cfg.opaEvaluator,
		application:             application,
		decisionInputHandler:    cfg.decisionInputHandler,
		claimsVerifier:          cfg.claimsVerifier,
		entitledServices:        cfg.entitledServices,
		acctEntitlementsApi:     cfg.acctEntitlementsApi,
		currUserCompartmentsApi: cfg.currUserCompartmentsApi,
		endpointModifier:        cfg.endpointModifier,
	}
	return &a
}

// Evaluate evaluates the authorization for the given endpoint and request.
func (a *httpAuthorizer) Evaluate(ctx context.Context, endpoint string, req interface{}, opaEvaluator az.OpaEvaluator) (bool, context.Context, error) {
	// Extract the logger from the context
	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	// Get the bearer token from the request
	bearer, err := util.GetBearerFromRequest(req.(*http.Request))
	if err != nil {
		logger.WithError(err).Error("get_bearer_from_request")
		return false, ctx, exception.ErrInvalidArg
	}

	// Verify the bearer token and get the raw JWT
	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = commonClaim.UnverifiedClaimFromBearers
	}
	rawJWT, errs := claimsVerifier([]string{bearer}, nil)
	if len(errs) > 0 {
		return false, ctx, exception.NewHttpError(
			exception.WithError(errors.Join(errs...)),
			exception.WithHttpStatus(http.StatusUnauthorized))
	}

	// Get the request ID from the request
	reqID := util.GetRequestIdFromRequest(req.(*http.Request))

	// Modify the endpoint if necessary
	pargsEndpoint := endpoint
	if a.endpointModifier != nil {
		pargsEndpoint = a.endpointModifier.getModifiedEndpoint(pargsEndpoint)
	}

	// Prepare the OPA request payload
	opaReq := opautil.Payload{
		Endpoint:         pargsEndpoint,
		FullMethod:       endpoint,
		Application:      a.application,
		JWT:              rawJWT,
		RequestID:        reqID,
		EntitledServices: a.entitledServices,
	}

	// Get the decision input for the endpoint and request
	decisionInput, err := a.decisionInputHandler.GetDecisionInput(ctx, endpoint, req)
	if decisionInput == nil || err != nil {
		logger.WithFields(log.Fields{
			"endpoint": endpoint,
		}).WithError(err).Error("get_decision_input")
		return false, ctx, exception.ErrInvalidArg
	}

	opaReq.DecisionInput = *decisionInput

	// TODO: Add tracing for the middleware
	// opaReqJSON, err := json.Marshal(opaReq)
	// if err != nil {
	// 	logger.WithFields(log.Fields{
	// 		"opaReq": opaReq,
	// 	}).WithError(err).Error("opa_request_json_marshal")
	// 	return false, ctx, exception.ErrInvalidArg
	// }

	now := time.Now()
	obfuscatedOpaReq := opautil.ShortenPayloadForDebug(opaReq)
	logger.WithFields(log.Fields{
		"opaReq": obfuscatedOpaReq,
	}).Debug("opa_authorization_request")

	// TODO: Add tracing for the middleware
	// Start a new trace span
	// ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, endpoint))
	// {
	// 	span.Annotate([]trace.Attribute{
	// 		trace.StringAttribute("in", string(opaReqJSON)),
	// 	}, "in")
	// }

	// Prepare the OPA input based on the decision document
	var opaInput interface{}
	opaInput = opaReq
	if len(decisionInput.DecisionDocument) > 0 {
		opaInput = opautil.OPARequest{Input: &opaReq}
	}

	var opaResp opautil.OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, opaInput, &opaResp)
	defer func() {
		// TODO: Add tracing for the middleware
		// span.SetStatus(trace.Status{
		// 	Code:    int32(grpc.Code(err)),
		// 	Message: grpc.ErrorDesc(err),
		// })
		// span.End()
		logger.WithFields(log.Fields{
			"opaResp": opaResp,
			"elapsed": time.Since(now),
		}).Debug("authorization_result")
	}()
	if err != nil {
		return false, ctx, err
	}

	// Extract the nested result if present
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

	// Log non-error OPA responses
	{
		// TODO: Add tracing for the middleware
		// raw, _ := json.Marshal(opaResp)
		// span.Annotate([]trace.Attribute{
		// 	trace.StringAttribute("out", string(raw)),
		// }, "out")
	}

	// Add raw entitled_features data to the context
	//REVIEW: is it needed for http?
	ctx = opaResp.AddRawEntitledFeatures(ctx)

	// Add obligations data to the context
	//REVIEW: is it needed for http?
	ctx, err = opautil.AddObligations(ctx, opaResp)
	if err != nil {
		logger.WithField("opaResp", fmt.Sprintf("%#v", opaResp)).WithError(err).Error("parse_obligations_error")
	}

	// Check if the authorization is allowed
	if !opaResp.Allow() {
		return false, ctx, exception.ErrForbidden
	}

	return true, ctx, nil
}

// OpaQuery executes a custom OPA query with the given decision document, request, and response.
func (a *httpAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	if a.opaEvaluator != nil {
		return a.opaEvaluator(ctx, decisionDocument, opaReq, opaResp)
	}

	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, opaReq, opaResp)
	// TODO: allow overriding logger
	if err != nil {
		httpErr := exception.GrpcToHttpError(err)
		logger.WithError(httpErr).Error("opa_policy_engine_request_error")
		return exception.AbstractError(httpErr)
	}
	logger.WithField("opaResp", opaResp).Debug("opa_policy_engine_response")
	return nil
}

// AffirmAuthorization makes an authz request to sidecar-OPA.
// If authorization is permitted, error returned is nil,
// and a new context is returned, possibly containing obligations.
// Caller must further evaluate obligations if required.
func (a *httpAuthorizer) AffirmAuthorization(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
	logger := ctxlogrus.Extract(ctx)
	var (
		ok     bool
		newCtx context.Context
		err    error
	)

	ok, newCtx, err = a.Evaluate(ctx, fullMethod, req, a.OpaQuery)
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
