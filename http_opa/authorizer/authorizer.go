package authorizer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/infobloxopen/atlas-authz-middleware/common"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/exception"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/util"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	log "github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

// SERVICENAME is the name of the Opa service.
var SERVICENAME = "opa"

// OpaEvaluator is a function type for evaluating Opa decisions.
type OpaEvaluator func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

// ClaimsVerifier is a function type for verifying claims.
type ClaimsVerifier func([]string, []string) (string, []error)

// HTTPAuthorizer is an interface for making arbitrary requests to Opa and evaluating authorization decisions.
type HTTPAuthorizer interface {
	// Evaluate evaluates the authorization policy for the given request.
	// It takes the context, full method name, request object, and an OpaEvaluator as input.
	// It returns a boolean indicating whether the request is authorized, a modified context,
	// and an error if any.
	Evaluate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes a query against the OPA (Open Policy Agent) with the specified decision document.
	// If the decision document is an empty string, the query is executed against the default decision document
	// configured in OPA.
	// It takes the context, decision document name, OPA request object, and OPA response object as input.
	// It returns an error if any.
	OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error
}

// httpAuthorizer is an implementation of the HTTPAuthorizer interface.
type httpAuthorizer struct {
	application          string
	clienter             opa_client.Clienter
	opaEvaluator         OpaEvaluator
	decisionInputHandler DecisionInputHandler
	claimsVerifier       ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
	endpointModifier     *EndpointModifier
}

var defDecisionInputer = new(DefaultDecisionInputer)

// NewHttpAuthorizer creates a new instance of the HTTPAuthorizer interface.
func NewHttpAuthorizer(application string, opts ...Option) HTTPAuthorizer {
	// Configuration options for the authorizer
	cfg := &Config{
		address:              opa_client.DefaultAddress,
		decisionInputHandler: defDecisionInputer,
		claimsVerifier:       commonClaim.UnverifiedClaimFromBearers,
		acctEntitlementsApi:  DefaultAcctEntitlementsApiPath,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	clienter := cfg.clienter
	if clienter == nil {
		clienter = opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli))
	}

	a := httpAuthorizer{
		clienter:             clienter,
		opaEvaluator:         cfg.opaEvaluator,
		application:          application,
		decisionInputHandler: cfg.decisionInputHandler,
		claimsVerifier:       cfg.claimsVerifier,
		entitledServices:     cfg.entitledServices,
		acctEntitlementsApi:  cfg.acctEntitlementsApi,
		endpointModifier:     cfg.endpointModifier,
	}
	return &a
}

// Evaluate evaluates the authorization decision for a given request.
func (a *httpAuthorizer) Evaluate(ctx context.Context, endpoint string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	// Extract the logger from the context
	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	// Get the bearer token from the request
	bearer, err := util.GetBearerFromRequest(req.(*http.Request))
	if err != nil {
		logger.WithError(err).Error("get_bearer_from_request")
		return false, ctx, exception.ErrForbidden
	}

	// Verify the bearer token and get the raw JWT
	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = commonClaim.UnverifiedClaimFromBearers
	}
	rawJWT, errs := claimsVerifier([]string{bearer}, nil)
	if len(errs) > 0 {
		return false, ctx, exception.NewHttpError(
			exception.WithError(multierr.Combine(errs...)),
			exception.WithHttpStatus(http.StatusUnauthorized))
	}

	// Get the request ID from the request
	reqID := util.GetRequestIdFromRequest(req.(*http.Request))

	// Modify the endpoint if necessary
	pargsEndpoint := endpoint
	if a.endpointModifier != nil {
		pargsEndpoint = a.endpointModifier.getModifiedEndpoint(pargsEndpoint)
	}

	// Create the Opa request payload
	opaReq := Payload{
		Endpoint:         pargsEndpoint,
		FullMethod:       endpoint,
		Application:      a.application,
		JWT:              common.RedactJWT(rawJWT),
		RequestID:        reqID,
		EntitledServices: a.entitledServices,
	}

	// Get the decision input for the request
	decisionInput, err := a.decisionInputHandler.GetDecisionInput(ctx, endpoint, req)
	if decisionInput == nil || err != nil {
		logger.WithFields(log.Fields{
			"endpoint": endpoint,
		}).WithError(err).Error("get_decision_input")
		return false, ctx, exception.ErrInvalidArg
	}

	opaReq.DecisionInput = *decisionInput

	//TODO: add tracing for the middleware similar to the one in the grpc interceptor

	// Marshal the Opa request payload to JSON
	// opaReqJSON, err := json.Marshal(opaReq)
	// if err != nil {
	// 	logger.WithFields(log.Fields{
	// 		"opaReq": opaReq,
	// 	}).WithError(err).Error("opa_request_json_marshal")
	// 	return false, ctx, exception.ErrInvalidArg
	// }

	// Start a trace span for the Opa request
	now := time.Now()
	obfuscatedOpaReq := ShortenPayloadForDebug(opaReq)
	logger.WithFields(log.Fields{
		"opaReq": obfuscatedOpaReq,
	}).Debug("opa_authorization_request")

	//TODO: add tracing for the middleware similar to the one in the grpc interceptor
	// ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, endpoint))
	// {
	// 	span.Annotate([]trace.Attribute{
	// 		trace.StringAttribute("in", string(opaReqJSON)),
	// 	}, "in")
	// }

	// Prepare the Opa input based on the decision document
	var opaInput interface{}
	opaInput = opaReq
	if len(decisionInput.DecisionDocument) > 0 {
		opaInput = OPARequest{Input: &opaReq}
	}

	// Execute the Opa evaluation
	var opaResp OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, opaInput, &opaResp)
	defer func() {
		//TODO: add tracing for the middleware similar to the one in the grpc interceptor
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

	// Extract the nested result if necessary
	nestedResultVal, resultIsNested := opaResp["result"]
	if resultIsNested {
		nestedResultMap, ok := nestedResultVal.(map[string]interface{})
		if ok {
			opaResp = OPAResponse{}
			for k, v := range nestedResultMap {
				opaResp[k] = v
			}
		}
	}

	// Log the Opa response
	{
		//TODO: add tracing for the middleware similar to the one in the grpc interceptor
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
	ctx, err = AddObligations(ctx, opaResp)
	if err != nil {
		logger.WithField("opaResp", fmt.Sprintf("%#v", opaResp)).WithError(err).Error("parse_obligations_error")
	}

	// Check if the request is authorized
	if !opaResp.Allow() {
		return false, ctx, exception.ErrForbidden
	}

	return true, ctx, nil
}

// OpaQuery executes a query against Opa.
func (a *httpAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	if a.opaEvaluator != nil {
		return a.opaEvaluator(ctx, decisionDocument, opaReq, opaResp)
	}

	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, opaReq, opaResp)
	if err != nil {
		httpErr := exception.GrpcToHttpError(err)
		logger.WithError(httpErr).Error("opa_policy_engine_request_error")
		return exception.AbstractError(httpErr)
	}
	logger.WithField("opaResp", opaResp).Debug("opa_policy_engine_response")
	return nil
}
