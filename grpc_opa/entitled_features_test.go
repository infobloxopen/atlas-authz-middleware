package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

const (
	succeed = "\u2713"
	failed  = "\u2717"
	red     = "\033[31m"
	green   = "\033[32m"
	reset   = "\033[0m"
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
		regoRespJSON: `{
			"allow": true
		}`,
		expectNilCtxVal:  true,
		expectFlattenErr: false,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON: `{
			"allow": true,
			"entitled_features": null
		}`,
		expectNilCtxVal:  true,
		expectFlattenErr: false,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON: `{
			"allow": true,
			"entitled_features": {}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: false,
		expectFlattenVal: []string{},
	},
	{
		regoRespJSON: `{
			"allow": true,
			"entitled_features": {"null": null}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: false,
		expectFlattenVal: []string{},
	},
	{
		regoRespJSON: `{
			"allow": true,
			"entitled_features": "bad entitled_features value"
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: true,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON: `{
			"allow": true,
			"entitled_features": {"str": "str"}
		}`,
		expectNilCtxVal:  false,
		expectFlattenErr: true,
		expectFlattenVal: nil,
	},
	{
		regoRespJSON: `{
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

func Test_opbench_ToJSONBArrStmt(t *testing.T) {
	tests := []struct {
		name    string
		rego    string
		want    string
		wantErr bool
	}{
		{
			name: "OneSvcOneFeatureOk",
			rego: `{
				"allow": true,
				"entitled_features": {
					"license": [ "td" ]
				}
			}`,
			want:    "array['license.td']",
			wantErr: false,
		},
		{
			name: "OneSvcManyFeaturesOk",
			rego: `{
				"allow": true,
				"entitled_features": {
					"license": [ "td", "dhcp", "dns" ]
				}
			}`,
			want:    "array['license.dhcp', 'license.dns', 'license.td']",
			wantErr: false,
		},
		{
			name: "ManySvcsManyFeaturesOk",
			rego: `{
				"allow": true,
				"entitled_features": {
					"license": [ "td", "dhcp", "dns" ],
					"license2": [ "td" ]
				}
			}`,
			want:    "array['license.dhcp', 'license.dns', 'license.td', 'license2.td']",
			wantErr: false,
		},
		{
			name: "ManySvcsEmptyFeaturesOk",
			rego: `{
				"allow": true,
				"entitled_features": {
					"license": [],
					"license2": []
				}
			}`,
			want:    "",
			wantErr: false,
		},
		{
			name: "EmptyEntitlsOk",
			rego: `{
				"allow": true,
				"entitled_features": {}
			}`,
			want:    "",
			wantErr: false,
		},
		{
			name: "NulEntitlsOk",
			rego: `{
				"allow": true,
				"entitled_features": null
			}`,
			want:    "",
			wantErr: false,
		},
		{
			name: "MissingEntitlsOk",
			rego: `{
				"allow": true
			}`,
			want:    "",
			wantErr: false,
		},
		{
			name: "EntitlsNulSvcOk",
			rego: `{
				"allow": true,
 	            "entitled_features": {"null": null}
			}`,
			want:    "",
			wantErr: false,
		},
		{
			name: "InvalidValErr",
			rego: `{
				"allow": true,
				"entitled_features": "invalid val"
			}`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opaResp OPAResponse
			jsonErr := json.Unmarshal([]byte(tt.rego), &opaResp)
			if jsonErr != nil {
				t.Fatalf("JSON unmarshal error passing data: %s", tt.rego)
			}
			ctx := opaResp.AddRawEntitledFeatures(context.Background())

			got, log, err := EntitlsCtxOp(ctx).ToJSONBArrStmt()
			t.Log(log)

			if err != nil {
				if tt.wantErr {
					t.Logf("\t%s test is passed", succeed)
					return
				} else {
					t.Errorf("\t%s unexpected error"+
						"\nGot: "+red+"%v"+reset+"\nWant: "+green+"%t"+reset,
						failed, err, tt.wantErr)
					return
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				vs := fmt.Sprintf("\t%s difference in got vs want statment"+
					"\nGot: "+red+" \n\n%s\n\n "+reset+"\nWant: "+green+"\n\n%s\n\n"+reset,
					failed, got, tt.want)
				t.Errorf(vs)
				return
			} else {
				t.Logf("\t%s test is passed", succeed)
			}
		})
	}
}
