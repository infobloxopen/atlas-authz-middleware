package grpc_opa_middleware

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EntitledFeaturesKeyType is the type of the entitled_features key stored in the caller's context
type EntitledFeaturesKeyType string

// EntitledFeaturesKey is the entitled_features key stored in the caller's context.
// It is also the entitled_features key in the OPA response.
const EntitledFeaturesKey = EntitledFeaturesKeyType("entitled_features")

// ErrInvalidEntitledFeatures is returned upon invalid entitled_features
var ErrInvalidEntitledFeatures = status.Errorf(codes.Internal, "Invalid entitled_features")

// AddRawEntitledFeatures adds raw entitled_features (if they exist) from OPAResponse to context
// The raw JSON-unmarshaled entitled_features is of the form:
//   map[string]interface {}{"lic":[]interface {}{"dhcp", "ipam"}, "rpz":[]interface {}{"bogon", "malware"}}}
func (o OPAResponse) AddRawEntitledFeatures(ctx context.Context) context.Context {
	efIfc, ok := o[string(EntitledFeaturesKey)]
	if ok {
		ctx = context.WithValue(ctx, EntitledFeaturesKey, efIfc)
	}
	return ctx
}

// FlattenRawEntitledFeatures flattens raw entitled_features into an array
// The raw JSON-unmarshaled entitled_features is of the form:
//   map[string]interface {}{"lic":[]interface {}{"dhcp", "ipam"}, "rpz":[]interface {}{"bogon", "malware"}}}
// Returns flattened array of the form:
//   []string{"lic.dhcp", "lic.ipam", "rpz.bogon", "rpz.malware"}
func FlattenRawEntitledFeatures(efIfc interface{}) ([]string, error) {
	if IsNilInterface(efIfc) {
		return nil, nil
	}

	efMapIfc, ok := efIfc.(map[string]interface{})
	if !ok {
		fmt.Printf("FlattenRawEntitledFeatures: fail efIfc.(map[string]interface{}) efIfc=%#v\n", efIfc)
		return nil, ErrInvalidEntitledFeatures
	}

	result := []string{}
	for svcName, featIfc := range efMapIfc {
		if IsNilInterface(featIfc) {
			continue
		}

		featArrIfc, ok := featIfc.([]interface{})
		if !ok {
			fmt.Printf("FlattenRawEntitledFeatures: fail featIfc.([]interface) featIfc=%#v\n", featIfc)
			return nil, ErrInvalidEntitledFeatures
		}

		for _, oneFeatIfc := range featArrIfc {
			if IsNilInterface(oneFeatIfc) {
				continue
			}

			oneFeatStr, ok := oneFeatIfc.(string)
			if !ok {
				fmt.Printf("FlattenRawEntitledFeatures: fail oneFeatIfc.(string) oneFeatIfc=%#v\n", oneFeatIfc)
				return nil, ErrInvalidEntitledFeatures
			}

			flatten := svcName + "." + oneFeatStr
			result = append(result, flatten)
		}
	}

	return result, nil
}
