package goapi

import (
	"context"
	"reflect"
	"testing"
)

func Test_composeInput(t *testing.T) {
	type args struct {
		ctx     context.Context
		cfg     *Config
		method  string
		grpcReq interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    *InputPayload
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := composeInput(tt.args.ctx, tt.args.cfg, tt.args.method, tt.args.grpcReq)
			if (err != nil) != tt.wantErr {
				t.Errorf("composeInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("composeInput() got = %v, want %v", got, tt.want)
			}
		})
	}
}
