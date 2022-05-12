package goapi

import (
	"context"
	"fmt"

	logger "github.com/sirupsen/logrus"
)

// ResultMap unmarshals the response from OPA into a generic untyped structure
type ResultMap map[string]interface{}

// EntitledFeaturesKeyType is the type of the entitled_features key stored in the caller's context
type EntitledFeaturesKeyType string

const (
	ObKey = ObligationKey("obligations")
	// EntitledFeaturesKey is the entitled_features key stored in the caller's context.
	// It is also the entitled_features key in the OPA response.
	EntitledFeaturesKey = EntitledFeaturesKeyType("entitled_features")
)

func parseResult(ctx context.Context, result interface{}) (ResultMap, error) {
	m := make(ResultMap)
	switch v := result.(type) {
	case map[string]interface{}:
		m = v
	default:
		return nil, ErrInvalidArg // TODO
	}

	// When we query OPA without url path, it returns results NOT encapsulated inside "result":
	//   {"allow": true, ...}
	// When we query OPA with explicit decision document, it returns results encapsulated inside "result":
	//   {"result":{"allow": true, ...}}
	// (See comments in testdata/mock_system_main.rego)
	// If the JSON result document is nested within "result" wrapper map,
	// we extract the nested JSON document and throw away the "result" wrapper map.
	if nestedResult, found := m["result"]; found {
		if nestedResultMap, found := nestedResult.(map[string]interface{}); found {
			m = make(ResultMap)
			for k, v := range nestedResultMap {
				m[k] = v
			}
		}
	}

	// adding raw entitled_features data to context if present
	ctx = m.AddRawEntitledFeatures(ctx)

	var err error
	// adding obligations data to context if present
	ctx, err = addObligations(ctx, m)
	if err != nil {
		logger.WithField("result_map", fmt.Sprintf("%#v", m)).
			WithError(err).Error("parse_obligations_error")
		return nil, ErrInvalidObligations
	}

	return m, nil
}

// AddRawEntitledFeatures adds raw entitled_features (if they exist) from OPAResponse to context
// The raw JSON-unmarshaled entitled_features is of the form:
//   map[string]interface {}{"lic":[]interface {}{"dhcp", "ipam"}, "rpz":[]interface {}{"bogon", "malware"}}}
func (m ResultMap) AddRawEntitledFeatures(ctx context.Context) context.Context {
	efIfc, ok := m[string(EntitledFeaturesKey)]
	if ok {
		ctx = context.WithValue(ctx, EntitledFeaturesKey, efIfc)
	}
	return ctx
}

func addObligations(ctx context.Context, resMap ResultMap) (context.Context, error) {
	ob, err := resMap.Obligations()
	if ob != nil {
		ctx = context.WithValue(ctx, ObKey, ob)
	}
	return ctx, err
}

// Obligations parses the returned obligations and returns them in standard format
func (m ResultMap) Obligations() (*ObligationsNode, error) {
	if obIfc, ok := m[string(ObKey)]; ok {
		return parseOPAObligations(obIfc)
	}
	return nil, nil
}

// Allow determine if policy is allowed
func (m ResultMap) Allow() bool {
	allow, ok := m["allow"].(bool)
	if !ok {
		return false
	}
	return allow
}
