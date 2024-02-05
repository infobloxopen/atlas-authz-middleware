package authorizer

import (
	"context"

	"github.com/infobloxopen/atlas-authz-middleware/common"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/opautil"
)

// EntitledFeaturesKeyType is the type of the entitled_features key stored in the caller's context
type EntitledFeaturesKeyType string

// EntitledFeaturesKey is the entitled_features key stored in the caller's context.
// It is also the entitled_features key in the OPA response.
const EntitledFeaturesKey = EntitledFeaturesKeyType("entitled_features")

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
func (o OPAResponse) Obligations() (*opautil.ObligationsNode, error) {
	if obIfc, ok := o[string(ObKey)]; ok {
		return opautil.ParseOPAObligations(obIfc)
	}
	return nil, nil
}

func ShortenPayloadForDebug(full Payload) Payload {
	// This is a shallow copy
	shorten := Payload(full)
	shorten.JWT = common.RedactJWTForDebug(shorten.JWT)
	return shorten
}

func AddObligations(ctx context.Context, opaResp OPAResponse) (context.Context, error) {
	ob, err := opaResp.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, ObKey, ob)
	}
	return ctx, err
}

// AddRawEntitledFeatures adds raw entitled_features (if they exist) from OPAResponse to context
// The raw JSON-unmarshaled entitled_features is of the form:
//
//	map[string]interface {}{"lic":[]interface {}{"dhcp", "ipam"}, "rpz":[]interface {}{"bogon", "malware"}}}
func (o OPAResponse) AddRawEntitledFeatures(ctx context.Context) context.Context {
	efIfc, ok := o[string(EntitledFeaturesKey)]
	if ok {
		ctx = context.WithValue(ctx, EntitledFeaturesKey, efIfc)
	}
	return ctx
}
