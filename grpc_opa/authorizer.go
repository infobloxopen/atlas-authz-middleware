package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	athena_claims "github.com/infobloxopen/atlas-claims"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ABACKey is a context.Context key type
type ABACKey string
type ObligationKey string

const (
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
	ErrForbidden          = status.Errorf(codes.PermissionDenied, "Request forbidden: not authorized")
	ErrUnknown            = status.Errorf(codes.Unknown, "Unknown error")
	ErrInvalidArg         = status.Errorf(codes.InvalidArgument, "Invalid argument")
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
		address:              opa_client.DefaultAddress,
		decisionInputHandler: defDecisionInputer,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	//log.Debugf("cfg=%+v", *cfg)

	a := DefaultAuthorizer{
		clienter:             opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli)),
		application:          application,
		decisionInputHandler: cfg.decisionInputHandler,
	}
	return &a
}

type DefaultAuthorizer struct {
	application string
	clienter    opa_client.Clienter

	decisionInputHandler DecisionInputHandler
}

type Config struct {
	httpCli *http.Client
	// address to opa
	address string

	authorizer []Authorizer

	decisionInputHandler DecisionInputHandler
}

var claimsVerifier func([]string, []string) (string, []error)

// 	FullMethod is the full RPC method string, i.e., /package.service/method.
// e.g. fullmethod:  /service.TagService/ListRetiredTags PARGs endpoint: TagService/ListRetiredTags
func parseEndpoint(fullMethod string) string {
	byPackage := strings.Split(fullMethod, ".")
	endpoint := byPackage[len(byPackage)-1]
	return strings.Replace(endpoint, "/", ".", -1)
}

func (a *DefaultAuthorizer) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {

	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	bearer, newBearer := athena_claims.AuthBearersFromCtx(ctx)

	if claimsVerifier == nil {
		claimsVerifier = UnverifiedClaimFromBearers
	}

	rawJWT, errs := claimsVerifier([]string{bearer}, []string{newBearer})
	if len(errs) > 0 {
		return false, ctx, fmt.Errorf("%q", errs)
	}

	opaReq := Payload{
		Endpoint:    parseEndpoint(fullMethod),
		FullMethod:  fullMethod,
		Application: a.application,
		// FIXME: implement athena_claims.AuthBearersFromCtx
		JWT: redactJWT(rawJWT),
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
	logger.WithFields(log.Fields{
		"opaReq": opaReq,
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

	var opaResp OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, opaReq, &opaResp)
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

	// Log non-err opa responses
	{
		raw, _ := json.Marshal(opaResp)
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("out", string(raw)),
		}, "out")
	}

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
	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, opaReq, opaResp)
	// TODO: allow overriding logger
	if err != nil {
		grpcErr := opa_client.GRPCError(err)
		logger.WithError(grpcErr).Error("opa_policy_engine_request_error")
		return opaqueError(grpcErr)
	} else {
		logger.WithField("opaResp", opaResp).Debug("opa_policy_engine_response")
	}
	return err
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
	FullMethod string `json:"full_method"`
	JWT        string `json:"jwt"`
	DecisionInput
}

// OPARequest is used to query OPA
type OPARequest struct {
	// Document on OPA "" calls default document
	Document string
	// OPA expects this field to be called input
	Input *Payload `json:"input"`
}

// OPAResponse unmarshals the response from OPA
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
	if len(parts) > 0 {
		parts[len(parts)-1] = REDACTED
	}
	return strings.Join(parts, ".")
}

func addObligations(ctx context.Context, opaResp OPAResponse) (context.Context, error) {
	ob, err := opaResp.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, ObKey, ob)
	}
	return ctx, err
}
