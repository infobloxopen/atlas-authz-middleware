package goapi

import (
	"context"
	"encoding/json"
	"fmt"
	sdktest "github.com/open-policy-agent/opa/sdk/test"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/sdk"
)

const (
	succeed = "\u2713"
	failed  = "\u2717"
	red     = "\033[31m"
	green   = "\033[32m"
	reset   = "\033[0m"
)

func Test_autorizer_Authorize(t *testing.T) {
	// create a mock HTTP bundle server
	server := sdktest.MustNewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"example.rego": `
				package authz

				default allow := false

				allow {
					input.open == "sesame"
				}
			`,
	}))

	defer server.Stop()

	cfg := &Config{
		Applicaton:    "test-app",
		DecisionPath:  "/authz/allow",
		OPAConfigFile: createOPAConfigFile(server.URL(), "/bundles/bundle.tar.gz", ""),
	}

	a, err := NewAutorizer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		ctx     context.Context
		input   map[string]interface{}
		wantRes *sdk.DecisionResult
		wantErr bool
	}{
		{
			name: "SmokeTestOk",
			ctx:  context.Background(),
			input: map[string]interface{}{
				"open": "sesame",
			},
			wantRes: &sdk.DecisionResult{
				Result: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := a.Authorize(tt.ctx, tt.input)
			// check error
			if err != nil {
				if !tt.wantErr {
					t.Errorf("\t%s unexpected error when running %s test"+
						"\nGot: %s\nWant error: %t", failed, tt.name, err.Error(), tt.wantErr)
					return
				} else {
					t.Logf("\t%s %s test is passed", succeed, tt.name)
					return
				}
			}

			// check result
			t.Logf("Decision result: %+v", res)
			// remove ID as it gets regenerated on every run
			if r, ok := res.(*sdk.DecisionResult); ok {
				r.ID = ""
				res = r
			}

			if !reflect.DeepEqual(res, tt.wantRes) {
				resJSON, err := json.MarshalIndent(res, "", "    ")
				if err != nil {
					t.Errorf("JSON marshal error %v", err)
					return
				}

				wantResJSON, err := json.MarshalIndent(tt.wantRes, "", "    ")
				if err != nil {
					t.Errorf("JSON marshal error %v", err)
					return
				}

				vs := fmt.Sprintf("\t%s difference in got vs want autorization decision result "+
					"\nGot: "+red+" \n\n%s\n\n "+reset+"\nWant: "+green+"\n\n%s\n\n"+reset,
					failed, string(resJSON), string(wantResJSON))
				t.Errorf(vs)
				return
			}
			t.Logf("\t%s %s test is passed", succeed, tt.name)
		})
	}
}
