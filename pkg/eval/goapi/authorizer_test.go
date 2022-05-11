package goapi

import (
	"context"
	"encoding/json"
	"fmt"
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
	cfg := &Config{
		Applicaton: "test-app",
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
				"message": "world",
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
