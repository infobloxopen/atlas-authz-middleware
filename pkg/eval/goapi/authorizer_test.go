package goapi

import (
	"bytes"
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

func Test_Example(t *testing.T) {
	ctx := context.Background()

	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"example.rego": `
			package authz

			default allow := false

			allow {
				input.open == "sesame"
			}
		`,
	}))
	if err != nil {
		// handle error.
	}

	defer server.Stop()

	// provide the OPA configuration which specifies
	// fetching policy bundles from the mock server
	// and logging decisions locally to the console
	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		},
		"decision_logs": {
			"console": true
		}
	}`, server.URL()))

	// create an instance of the OPA object
	opa, err := sdk.New(ctx, sdk.Options{
		Config: bytes.NewReader(config),
	})

	if err != nil {
		// handle error.
	}

	defer opa.Stop(ctx)

	// get the named policy decision for the specified input
	if result, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/authz/allow", Input: map[string]interface{}{"open": "sesame"}}); err != nil {
		// handle error.
	} else if decision, ok := result.Result.(bool); !ok || !decision {
		// handle error.
	}
}

func Test_autorizer_Authorize(t *testing.T) {
	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"example.rego": `
				package authz

				default allow := false

				allow {
					input.open == "sesame"
				}
			`,
	}))
	if err != nil {
		t.Fatal(err)
	}

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
			wantRes: &sdk.DecisionResult{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := a.Authorize(tt.ctx, tt.input)
			// check error
			if err != nil && tt.wantErr {
				t.Errorf("\t%s unexpected error when running %s test"+
					"\nGot: %s\nWant error: %t", failed, tt.name, err.Error(), tt.wantErr)
				return
			} else {
				t.Logf("\t%s %s test is passed", succeed, tt.name)
				return
			}
			// check result
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
