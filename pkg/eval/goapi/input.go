package goapi

import (
	"context"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"strings"

	"github.com/infobloxopen/atlas-app-toolkit/requestid"
	"github.com/infobloxopen/atlas-authz-middleware/utils"
	atlas_claims "github.com/infobloxopen/atlas-claims"
	"github.com/sirupsen/logrus"
)

const (
	TypeKey = ABACKey("ABACType")
	VerbKey = ABACKey("ABACVerb")
)

// ABACKey is a context.Context key type
type ABACKey string
type ObligationKey string

type InputPayload struct {
	Endpoint    string `json:"endpoint"`
	Application string `json:"application"`
	// FullMethod is the full RPC method string, i.e., /package.service/method.
	FullMethod       string   `json:"full_method"`
	JWT              string   `json:"jwt"`
	RequestID        string   `json:"request_id"`
	EntitledServices []string `json:"entitled_services"`
	DecisionInput
}

type ClaimsVerifier func([]string, []string) (string, []error)

// DecisionInput is app/service-specific data supplied by app/service ABAC requests
type DecisionInput struct {
	Type             string        `json:"type"` // Object/resource-type to match
	Verb             string        `json:"verb"` // Verb to match
	SealCtx          []interface{} `json:"ctx"`  // Array of app/service-specific context data to match
	DecisionDocument string        `json:"-"`    // OPA decision document to query, by default "",
	// which is default decision document configured in OPA
}

// DecisionInputHandler ...
type DecisionInputHandler interface {
	// GetDecisionInput returns an app/service-specific DecisionInput.
	// A nil DecisionInput should NOT be returned unless error.
	// fullMethod is of the form "Service.FullMethod"
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

// 	FullMethod is the full RPC method string, i.e., /package.service/method.
// e.g. fullmethod:  /service.TagService/ListRetiredTags PARGs endpoint: TagService.ListRetiredTags
func parseEndpoint(fullMethod string) string {
	byPackage := strings.Split(fullMethod, ".")
	endpoint := byPackage[len(byPackage)-1]
	return strings.Replace(endpoint, "/", ".", -1)
}

func composeInput(ctx context.Context, cfg *Config, method string, grpcReq interface{}) (*InputPayload, error) {
	log := ctxlogrus.Extract(ctx).WithFields(logrus.Fields{
		"application": cfg.Applicaton,
	})

	// This fetches auth data from auth headers in metadata from context:
	// bearer = data from "authorization bearer" metadata header
	// newBearer = data from "set-authorization bearer" metadata header
	bearer, newBearer := atlas_claims.AuthBearersFromCtx(ctx)

	rawJWT, errs := cfg.claimsVerifier([]string{bearer}, []string{newBearer})
	if len(errs) > 0 {
		return nil, fmt.Errorf("%q", errs)
	}

	reqID, ok := requestid.FromContext(ctx)
	if !ok {
		reqID = "no-request-uuid"
	}

	decisionInput, err := cfg.decisionInputHandler.GetDecisionInput(ctx, method, grpcReq)
	if decisionInput == nil || err != nil {
		log.WithFields(logrus.Fields{
			"fullMethod": method,
		}).WithError(err).Error("get_decision_input")
		return nil, ErrInvalidArg
	}

	payload := InputPayload{
		Endpoint:         parseEndpoint(method),
		FullMethod:       method,
		Application:      cfg.Applicaton,
		JWT:              utils.RedactJWT(rawJWT), // FIXME: implement atlas_claims.AuthBearersFromCtx
		RequestID:        reqID,
		EntitledServices: cfg.entitledServices,
		DecisionInput:    *decisionInput,
	}

	p4debug := payload
	p4debug.JWT = utils.RedactJWT4Debug(p4debug.JWT)
	log.WithFields(logrus.Fields{
		"payload": p4debug,
	}).Debug("opa_request")

	return &payload, nil
}
