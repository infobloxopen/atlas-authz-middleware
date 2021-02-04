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
type ObligationsType [][]string

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
	ErrInvalidObligations = status.Errorf(codes.Internal, "Invalid obligations")
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
	GetDecisionInput(ctx context.Context, fullMethod string) (*DecisionInput, error)
}

// DefaultDecisionInputer is an example DecisionInputHandler that is used as default
type DefaultDecisionInputer struct{}

// GetDecisionInput is an example DecisionInputHandler that returns some decision input
// based on some incoming Context values.  App/services will most likely supply their
// own DecisionInputHandler using WithDecisionInputHandler option.
func (m *DefaultDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string) (*DecisionInput, error) {
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
type OpaEvaluator func(ctx context.Context, decisionDocument string, req, resp interface{}) error

// Authorizer interface is implemented for making arbitrary requests to Opa.
type Authorizer interface {
	// Evaluate is called with the request's method passing the request Context.
	// If the handler is executed, the request will be sent to Opa. Opa's response
	// will be unmarshaled using JSON into the provided response.
	// Evaluate returns true if the request is authorized. The context
	// will be passed to subsequent HTTP Handler.
	Evaluate(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error)

	// OpaQuery executes query of the specified decisionDocument against OPA.
	// If decisionDocument is "", then the query is executed against the default decision document configured in OPA.
	OpaQuery(ctx context.Context, decisionDocument string, req, resp interface{}) error
}

type AuthorizeFn func(ctx context.Context, fullMethodName string, opaEvaluator OpaEvaluator) (bool, context.Context, error)

func (a AuthorizeFn) OpaQuery(req, resp interface{}) error {
	return nil
}

func (a AuthorizeFn) Evaluate(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return a(ctx, fullMethod, opaEvaluator)
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

func (a *DefaultAuthorizer) Evaluate(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {

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

	request := Payload{
		Endpoint:    parseEndpoint(fullMethod),
		FullMethod:  fullMethod,
		Application: a.application,
		// FIXME: implement athena_claims.AuthBearersFromCtx
		JWT: redactJWT(rawJWT),
	}

	decisionInput, err := a.decisionInputHandler.GetDecisionInput(ctx, fullMethod)
	if decisionInput == nil || err != nil {
		logger.WithFields(log.Fields{
			"fullMethod": fullMethod,
		}).WithError(err).Error("get_decision_input")
		return false, ctx, ErrInvalidArg
	}
	//logger.Debugf("decisionInput=%+v", *decisionInput)
	request.DecisionInput = *decisionInput

	reqJSON, err := json.Marshal(request)
	if err != nil {
		logger.WithFields(log.Fields{
			"request": request,
		}).WithError(err).Error("request_json_marshal")
		return false, ctx, ErrInvalidArg
	}

	now := time.Now()
	logger.WithFields(log.Fields{
		"request": request,
		//"requestJSON": string(reqJSON),
	}).Debug("authorization_request")

	// To enable tracing, the context must have a tracer attached
	// to it. See the tracing documentation on how to do this.
	ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, fullMethod))
	{
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("in", string(reqJSON)),
		}, "in")
	}
	// FIXME: perhaps only inject these fields if this is the default handler

	var response OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, request, &response)
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
			"response": response,
			"elapsed":  time.Since(now),
		}).Debug("authorization_result")
	}()
	if err != nil {
		return false, ctx, err
	}

	// Log non-err responses
	{
		raw, _ := json.Marshal(response)
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("out", string(raw)),
		}, "out")
	}

	// adding obligations data to context if present
	ctx, err = addObligations(ctx, response)
	if err != nil {
		logger.WithField("response", fmt.Sprintf("%#v", response)).WithError(err).Error("parse_obligations_error")
	}

	if !response.Allow() {
		return false, ctx, ErrForbidden
	}

	return true, ctx, nil
}

func (a *DefaultAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, req, resp interface{}) error {
	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, req, resp)
	// TODO: allow overriding logger
	if err != nil {
		grpcErr := opa_client.GRPCError(err)
		logger.WithError(grpcErr).Error("policy_engine_request_error")
		return opaqueError(grpcErr)
	} else {
		logger.WithField("response", resp).Debug("policy_engine_response")
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
func (o OPAResponse) Obligations() (ObligationsType, error) {
	if _, ok := o[string(ObKey)]; !ok {
		return nil, nil
	}

	arrIfc, isArr := o[string(ObKey)].([]interface{})
	mapIfc, isMap := o[string(ObKey)].(map[string]interface{})

	if isArr {
		return parseObligationsArray(arrIfc)
	} else if isMap {
		return parseObligationsMap(mapIfc)
	}

	return nil, ErrInvalidObligations
}

// obligations json.Unmarshal()'d as type:
// []interface {}{[]interface {}{"ctx.metric == \"dhcp\""}}
func parseObligationsArray(arrIfc []interface{}) (ObligationsType, error) {
	result := ObligationsType{}

	for _, subIfc := range arrIfc {
		subResult := []string{}
		subArrIfc, ok := subIfc.([]interface{})

		if !ok {
			return nil, ErrInvalidObligations
		}

		for _, itemIfc := range subArrIfc {
			s, ok := itemIfc.(string)
			if !ok {
				return nil, ErrInvalidObligations
			}
			subResult = append(subResult, s)
		}

		result = append(result, subResult)
	}

	return result, nil
}

// obligations json.Unmarshal()'d as type:
// map[string]interface {}{"policy1_guid":map[string]interface {}{"stmt0":[]interface {}{"ctx.metric == \"dhcp\""}}}
func parseObligationsMap(mapIfc map[string]interface{}) (ObligationsType, error) {
	result := ObligationsType{}

	for _, subIfc := range mapIfc {
		subMapIfc, ok := subIfc.(map[string]interface{})

		if !ok {
			return nil, ErrInvalidObligations
		}

		for _, stmtIfc := range subMapIfc {
			subResult := []string{}
			subArrIfc, ok := stmtIfc.([]interface{})

			if !ok {
				return nil, ErrInvalidObligations
			}

			for _, itemIfc := range subArrIfc {
				s, ok := itemIfc.(string)
				if !ok {
					return nil, ErrInvalidObligations
				}
				subResult = append(subResult, s)
			}

			result = append(result, subResult)
		}
	}

	return result, nil
}

func redactJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) > 0 {
		parts[len(parts)-1] = REDACTED
	}
	return strings.Join(parts, ".")
}

func addObligations(ctx context.Context, response OPAResponse) (context.Context, error) {
	ob, err := response.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, ObKey, ob)
	}
	return ctx, err
}
