package wasm

import (
	"context"
	"reflect"
	"testing"
)

func Test_parseResult(t *testing.T) {
	type args struct {
		ctx    context.Context
		result interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    ResultMap
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResult(tt.args.ctx, tt.args.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseResult() got = %v, want %v", got, tt.want)
			}
		})
	}
}
