package wasm

import (
	"context"
	"github.com/open-policy-agent/opa/sdk"
	"reflect"
	"testing"
)

func Test_parseResult(t *testing.T) {
	type args struct {
		ctx    context.Context
		result *sdk.DecisionResult
	}
	tests := []struct {
		name    string
		args    args
		want    context.Context
		want1   ResultMap
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseResult(tt.args.ctx, tt.args.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseResult() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parseResult() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
