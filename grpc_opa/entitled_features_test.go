package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func Test_entitled_features_context(t *testing.T) {
	for idx, tst := range entitledFeaturesTest {
		var opaResp OPAResponse

		jsonErr := json.Unmarshal([]byte(tst.regoRespJSON), &opaResp)
		if jsonErr != nil {
			t.Errorf("tst#%d: FAIL: err=%s trying to json.Unmarshal: %s",
				idx, jsonErr, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: opaResp=%#v", idx, opaResp)

		ctx := context.Background()
		newCtx := opaResp.AddRawEntitledFeatures(ctx)

		efIfc := newCtx.Value(EntitledFeaturesKey)
		if tst.expectNilCtxVal && efIfc != nil {
			t.Errorf("tst#%d: FAIL: Got unexpected context.Value(%s): %#v",
				idx, string(EntitledFeaturesKey), efIfc)
		} else if !tst.expectNilCtxVal && efIfc == nil {
			t.Errorf("tst#%d: FAIL: Expected non-nil context.Value(%s), but got nil",
				idx, string(EntitledFeaturesKey))
		}

		efArr, flattenErr := FlattenRawEntitledFeatures(efIfc)
		if !tst.expectFlattenErr && flattenErr != nil {
			t.Errorf("tst#%d: FAIL: Got unexpected FlattenRawEntitledFeatures(%#v) err: %s", idx, efIfc, flattenErr)
		} else if tst.expectFlattenErr && flattenErr == nil {
			t.Errorf("tst#%d: FAIL: Expected FlattenRawEntitledFeatures(%#v) err, but got nil err", idx, efIfc)
		}

		if efArr == nil {
			continue
		}

		sort.Strings(efArr)
		sort.Strings(tst.expectFlattenVal)
		if !reflect.DeepEqual(tst.expectFlattenVal, efArr) {
			t.Errorf("tst#%d: FAIL: expectFlattenVal=%s\nefArr=%s",
				idx, tst.expectFlattenVal, efArr)
		}
	}
}

var entitledFeaturesTest = []struct {
	regoRespJSON     string
	expectNilCtxVal  bool
	expectFlattenErr bool
	expectFlattenVal []string
}{
	{
		regoRespJSON:     `{
			"allow": true
		}`,
		expectNilCtxVal:  true,
		expectFlattenErr: false,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": null
		}`,
		expectNilCtxVal:  true,
		expectFlattenErr: false,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": {}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: false,
		expectFlattenVal: []string{},
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": {"null": null}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: false,
		expectFlattenVal: []string{},
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": "bad entitled_features value"
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: true,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": {"str": "str"}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: true,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON:     `{
			"allow": true,
			"entitled_features": {
				"null": null,
				"lic": [ "dhcp", null, "ipam" ],
				"rpz": [ "bogon", null, "malware" ]
			}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: false,
		expectFlattenVal: []string{"lic.dhcp", "lic.ipam", "rpz.bogon", "rpz.malware"},
	},
}
