package opautil

import (
	"context"
	"strings"

	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
)

type Payload struct {
	Endpoint    string `json:"endpoint"`
	Application string `json:"application"`
	// FullMethod is the full RPC method string, i.e., /package.service/method.
	FullMethod       string   `json:"full_method"`
	JWT              string   `json:"jwt"`
	RequestID        string   `json:"request_id"`
	EntitledServices []string `json:"entitled_services"`
	az.DecisionInput
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
	if obIfc, ok := o[string(az.ObKey)]; ok {
		return ParseOPAObligations(obIfc)
	}
	return nil, nil
}

func RedactJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) > 0 {
		parts[len(parts)-1] = az.REDACTED
	}
	return strings.Join(parts, ".")
}

func RedactJWTForDebug(jwt string) string {
	parts := strings.Split(jwt, ".")
	// Redact signature, header and body since we do not want to display any for debug logging
	for i := range parts {
		parts[i] = parts[i][:Min(len(parts[i]), 16)] + "/" + az.REDACTED
	}
	return strings.Join(parts, ".")
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ShortenPayloadForDebug(full Payload) Payload {
	// This is a shallow copy
	shorten := Payload(full)
	shorten.JWT = RedactJWTForDebug(shorten.JWT)
	return shorten
}

func AddObligations(ctx context.Context, opaResp OPAResponse) (context.Context, error) {
	ob, err := opaResp.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, az.ObKey, ob)
	}
	return ctx, err
}
