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
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	atlas_claims "github.com/infobloxopen/atlas-claims"
)

// ABACKey is a context.Context key type
type ABACKey string
type ObligationKey string

const (
	// DefaultValidatePath is default OPA path to perform authz validation
	DefaultValidatePath = "v1/data/authz/rbac/validate_v1"

	REDACTED = "redacted"
	TypeKey  = ABACKey("ABACType")
	VerbKey  = ABACKey("ABACVerb")
	ObKey    = ObligationKey("obligations")
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

// DecisionInput is app/service-specific data supplied by app/service ABAC requests
type DecisionInput struct {
	Type             string        `json:"type"` // Object/resource-type to match
	Verb             string        `json:"verb"` // Verb to match
	SealCtx          []interface{} `json:"ctx"`  // Array of app/service-specific context data to match
	DecisionDocument string        `json:"-"`    // OPA decision document to query, by default "",
	// which is default decision document configured in OPA
}

// fullMethod is of the form "Service.FullMethod"
type DecisionInputHandler interface {
	// GetDecisionInput returns an app/service-specific DecisionInput.
	// A nil DecisionInput should NOT be returned unless error.
	GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error)
}

// DefaultDecisionInputer is an example DecisionInputHandler that is used as default
type DefaultDecisionInputer struct{}

func (m DefaultDecisionInputer) String() string {
	return "grpc_opa_middleware.DefaultDecisionInputer{}"
}

// GetDecisionInput is an example DecisionInputHandler that returns some decision input
// based on some incoming Context values.  App/services will most likely supply their
// own DecisionInputHandler using WithDecisionInputHandler option.
func (m *DefaultDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error) {
	var abacType string
	if v, ok := ctx.Value(TypeKey).(string); ok {
		abacType = v
	}

	var abacVerb string
	if v, ok := ctx.Value(VerbKey).(string); ok {
		abacVerb = v
	}

	decInp := DecisionInput{
		Type: abacType,
		Verb: abacVerb,
	}
	return &decInp, nil
}

var defDecisionInputer = new(DefaultDecisionInputer)

// OpaEvaluator implements calling OPA with a request and receiving the raw response
type OpaEvaluator func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error

// Authorizer interface is implemented for making arbitrary requests to Opa.
type Authorizer interface {
	// Evaluate is called with the grpc request's method passing the grpc request Context.
	// If the handler is executed, the request will be sent to Opa. Opa's response
	// will be unmarshaled using JSON into the provided response.
	// Evaluate returns true if the request is authorized. The context
	// will be passed to subsequent HTTP Handler.
	Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes query of the specified decisionDocument against OPA.
	// If decisionDocument is "", then the query is executed against the default decision document configured in OPA.
	OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error
}

type AuthorizeFn func(ctx context.Context, fullMethodName string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)

func (a AuthorizeFn) OpaQuery(opaReq, opaResp interface{}) error {
	return nil
}

func (a AuthorizeFn) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return a(ctx, fullMethod, grpcReq, opaEvaluator)
}

func NewDefaultAuthorizer(application string, opts ...Option) *DefaultAuthorizer {
	cfg := &Config{
		address:                   opa_client.DefaultAddress,
		decisionInputHandler:      defDecisionInputer,
		claimsVerifier:            UnverifiedClaimFromBearers,
		acctEntitlementsApi:       DefaultAcctEntitlementsApiPath,
		currUserCompartmentsApi:   DefaultCurrentUserCompartmentsPath,
		filterCompartmentPermsApi: DefaultFilterCompartmentPermissionsApiPath,
		filterCompartmentFeatsApi: DefaultFilterCompartmentFeaturesApiPath,
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
		clienter:                  clienter,
		opaEvaluator:              cfg.opaEvaluator,
		application:               application,
		decisionInputHandler:      cfg.decisionInputHandler,
		claimsVerifier:            cfg.claimsVerifier,
		entitledServices:          cfg.entitledServices,
		acctEntitlementsApi:       cfg.acctEntitlementsApi,
		currUserCompartmentsApi:   cfg.currUserCompartmentsApi,
		filterCompartmentPermsApi: cfg.filterCompartmentPermsApi,
		filterCompartmentFeatsApi: cfg.filterCompartmentFeatsApi,
	}
	return &a
}

type DefaultAuthorizer struct {
	application               string
	clienter                  opa_client.Clienter
	opaEvaluator              OpaEvaluator
	decisionInputHandler      DecisionInputHandler
	claimsVerifier            ClaimsVerifier
	entitledServices          []string
	acctEntitlementsApi       string
	currUserCompartmentsApi   string
	filterCompartmentPermsApi string
	filterCompartmentFeatsApi string
}

type Config struct {
	httpCli *http.Client
	// address to opa
	address string

	clienter                  opa_client.Clienter
	opaEvaluator              OpaEvaluator
	authorizer                []Authorizer
	decisionInputHandler      DecisionInputHandler
	claimsVerifier            ClaimsVerifier
	entitledServices          []string
	acctEntitlementsApi       string
	currUserCompartmentsApi   string
	filterCompartmentPermsApi string
	filterCompartmentFeatsApi string
}

type ClaimsVerifier func([]string, []string) (string, []error)

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

func (a *DefaultAuthorizer) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {

	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	// This fetches auth data from auth headers in metadata from context:
	// bearer = data from "authorization bearer" metadata header
	// newBearer = data from "set-authorization bearer" metadata header
	bearer, newBearer := atlas_claims.AuthBearersFromCtx(ctx)

	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = UnverifiedClaimFromBearers
	}

	rawJWT, errs := claimsVerifier([]string{bearer}, []string{newBearer})
	if len(errs) > 0 {
		return false, ctx, fmt.Errorf("%q", errs)
	}

	reqID, ok := requestid.FromContext(ctx)
	if !ok {
		reqID = "no-request-uuid"
	}

	opaReq := Payload{
		Endpoint:    parseEndpoint(fullMethod),
		FullMethod:  fullMethod,
		Application: a.application,
		// FIXME: implement atlas_claims.AuthBearersFromCtx
		JWT:              rawJWT,
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
	obfuscatedOpaReq := shortenPayloadForDebug(opaReq)
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
		opaInput = OPARequest{Input: &opaReq}
	}

	var opaResp OPAResponse
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
			opaResp = OPAResponse{}
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
	ctx, err = addObligations(ctx, opaResp)
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
		return opaqueError(grpcErr)
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

// opaqueError trims some privileged information from errors
// as these get sent directly as grpc responses
func opaqueError(err error) error {

	switch status.Code(err) {
	case codes.Unavailable:
		return opa_client.ErrServiceUnavailable
	case codes.Unknown:
		return opa_client.ErrUnknown
	}

	return err
}

type Payload struct {
	Endpoint    string `json:"endpoint"`
	Application string `json:"application"`
	// FullMethod is the full RPC method string, i.e., /package.service/method.
	FullMethod       string   `json:"full_method"`
	JWT              string   `json:"jwt"`
	RequestID        string   `json:"request_id"`
	EntitledServices []string `json:"entitled_services"`
	DecisionInput
}

// OPARequest is used to query OPA
type OPARequest struct {
	// OPA expects field called "input" to contain input payload
	Input interface{} `json:"input"`
}

// OPAResponse unmarshals the response from OPA into a generic untyped structure
type OPAResponse map[string]interface{}

// Allow determine if policy is allowed
func (o OPAResponse) Allow() bool {
	allow, ok := o["allow"].(bool)
	if !ok {
		return false
	}
	return allow
}

// Obligations parses the returned obligations and returns them in standard format
func (o OPAResponse) Obligations() (*ObligationsNode, error) {
	if obIfc, ok := o[string(ObKey)]; ok {
		return parseOPAObligations(obIfc)
	}
	return nil, nil
}

func redactJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	// Redact signature
	if len(parts) > 0 {
		parts[len(parts)-1] = REDACTED
	}
	return strings.Join(parts, ".")
}

func redactJWTForDebug(jwt string) string {
	parts := strings.Split(jwt, ".")
	// Redact header/payload/signature, since we do not want to display any for debug logging
	for i := range parts {
		parts[i] = parts[i][:min(len(parts[i]), 16)] + "/" + REDACTED
	}
	return strings.Join(parts, ".")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func shortenPayloadForDebug(full Payload) Payload {
	// This is a shallow copy
	shorten := Payload(full)
	shorten.JWT = redactJWTForDebug(shorten.JWT)
	return shorten
}

func addObligations(ctx context.Context, opaResp OPAResponse) (context.Context, error) {
	ob, err := opaResp.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, ObKey, ob)
	}
	return ctx, err
}
