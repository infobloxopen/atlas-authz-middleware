package opautil

import "context"

// EntitledFeaturesKeyType is the type of the entitled_features key stored in the caller's context
type EntitledFeaturesKeyType string

// EntitledFeaturesKey is the entitled_features key stored in the caller's context.
// It is also the entitled_features key in the OPA response.
const EntitledFeaturesKey = EntitledFeaturesKeyType("entitled_features")

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
