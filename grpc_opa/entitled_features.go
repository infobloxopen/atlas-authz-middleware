package grpc_opa_middleware

import (
	"context"
	"fmt"
	"sort"
	"strings"

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
		return nil, ErrInvalidEntitledFeatures
	}

	result := []string{}
	for svcName, featIfc := range efMapIfc {
		if IsNilInterface(featIfc) {
			continue
		}

		featArrIfc, ok := featIfc.([]interface{})
		if !ok {
			return nil, ErrInvalidEntitledFeatures
		}

		for _, oneFeatIfc := range featArrIfc {
			if IsNilInterface(oneFeatIfc) {
				continue
			}

			oneFeatStr, ok := oneFeatIfc.(string)
			if !ok {
				return nil, ErrInvalidEntitledFeatures
			}

			flatten := svcName + "." + oneFeatStr
			result = append(result, flatten)
		}
	}

	return result, nil
}

type opbench struct {
	val map[string][]string
	err error
	log string
}

// EntitlsCtxOp is a simple operator to manipulate
// over entitled features in context. It retrieves
// entitled features from the context and converts
// them to a structure that is easy to operato on.
// Returned value includes only unimported fields
// and is designed to chain other methods that it
// has.
func EntitlsCtxOp(ctx context.Context) *opbench {
	op := opbench{
		val: map[string][]string{},
		log: fmt.Sprintf("ctx (%s) -> ", EntitledFeaturesKey),
	}
	switch v := ctx.Value(EntitledFeaturesKey).(type) {
	case map[string]interface{}:
		op.log += fmt.Sprintf("map[string]interface{} (%+v) -> ", v)
		for k, vs := range v {
			switch vv := vs.(type) {
			case []interface{}:
				op.log += k + ":[]interface{"
				div := ""
				for i, f := range vv {
					if i > 0 {
						div = ", "
					}

					switch vvv := f.(type) {
					case string:
						op.log += fmt.Sprintf("%s%q", div, vvv)
						op.val[k] = append(op.val[k], vvv)
					case nil:
						op.log += "nil (missing string value for key: " + k + ")"
					default:
						op.log += fmt.Sprintf("%T (unimplemented type for key: %v)", vv, k)
						op.err = ErrInvalidEntitledFeatures
						return &op
					}
				}
				op.log += "} -> "
			case nil:
				op.log += "nil (missing value for key: " + k + ")"
			default:
				op.log += fmt.Sprintf("%T (unimplemented type for key: %v)", vv, k)
				op.err = ErrInvalidEntitledFeatures
				return &op
			}
		}
	case nil:
		op.log += "nil (missing)"
	default:
		op.log += fmt.Sprintf("%T (unimplemented type)", v)
		op.err = ErrInvalidEntitledFeatures
	}
	return &op
}

// ToJSONBArrStmt converts entitled features to an array
// statement for futher use with existence JSONB operator.
// Array elements are sorted in increasing order for easier
// testing and reading. The result is finally processed by
// PostgreSQL as '{license.td,license.se}'::text[].
// The method also returns an error and a trace log entry
// reflecting all data manipulations up to the end result.
// Example of successful log entry:
// ctx (entitled_features) -> map[string]interface{}
// (map[license:[td]]) -> license:[]interface{"td"} ->
// array['license.td']
func (op *opbench) ToJSONBArrStmt() (string, string, error) {
	switch {
	case op.err != nil:
		return "", op.log, op.err
	case len(op.val) == 0:
		return "", op.log, nil
	}

	var s []string
	for k, vs := range op.val {
		for _, v := range vs {
			s = append(s, "'"+k+"."+v+"'")
		}
	}

	sort.Strings(s)
	a := "array[" + strings.Join(s, ", ") + "]"

	op.log += a
	return a, op.log, nil
}
