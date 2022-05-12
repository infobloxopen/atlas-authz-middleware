package goapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

const (
	succeed = "\u2713"
	failed  = "\u2717"
	red     = "\033[31m"
	green   = "\033[32m"
	reset   = "\033[0m"
)

type EmptyObj struct {
	Obj string `json:"obj,omitempty"`
}

func Test_autorizer_Authorize(t *testing.T) {
	// https://github.com/stevef1uk/opa-bundle-server
	hf := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Received a request: %+v", r)
		data, err := ioutil.ReadFile("./data_test/bundle.tar.gz")
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+"bundle.tar.gz")
		w.Header().Set("Content-Transfer-Encoding", "binary")
		w.Header().Set("Expires", "0")
		http.ServeContent(w, r, "Fred", time.Now(), bytes.NewReader(data))
	}

	svr := httptest.NewServer(http.HandlerFunc(hf))
	defer svr.Close()

	cfg := &Config{
		Applicaton:    "test-app",
		DecisionPath:  DefaultDecisionPath,
		OPAConfigFile: createOPAConfigFile(svr.URL, "/bundles/bundle.tar.gz", ""),
	}

	a, err := NewAutorizer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		ctx     context.Context
		cfg     *Config
		input   *InputPayload
		wantRes ResultMap
		wantErr bool
	}{
		{
			name: "SmokeTestOk",
			ctx:  context.Background(),
			cfg:  &Config{},
			input: &InputPayload{
				Endpoint:    "TagService.List",
				Application: "atlas.tagging",
				FullMethod:  "/service.TagService/List",
				JWT:         "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNzciLCJpZGVudGl0eV91c2VyX2lkIjoiOTBjZDlmYzItYmQ1ZC00YmU4LWI3ZmYtYWYxNzVlNGVjMDU2IiwidXNlcm5hbWUiOiJha3VtYXJAaW5mb2Jsb3guY29tIiwiYWNjb3VudF9pZCI6IjIwMDUyNjQiLCJjc3BfYWNjb3VudF9pZCI6MjAwNTI2NCwiaWRlbnRpdHlfYWNjb3VudF9pZCI6IjkzZWU2MDA3LTBhN2EtNGUxYS04MGRkLTI1OGVmNjhiNmZmNSIsImFjY291bnRfbmFtZSI6Ikhvc3QgVjIiLCJhY2NvdW50X251bWJlciI6IjIwMDUyNjQiLCJjb21wYW55X251bWJlciI6MTAwMDA1NTAxLCJhY2NvdW50X3N0b3JhZ2VfaWQiOjIzMDUyNjQsInNmZGNfYWNjb3VudF9pZCI6IkJMT1hJTlQ5OTg4Nzc2NjU5OSIsImdyb3VwcyI6WyJ1c2VyIiwiYWN0X2FkbWluIiwiaWItYWNjZXNzLWNvbnRyb2wtYWRtaW4iLCJpYi1pbnRlcmFjdGl2ZS11c2VyIl0sInN1YmplY3QiOnsiaWQiOiJha3VtYXJAaW5mb2Jsb3guY29tIiwic3ViamVjdF90eXBlIjoidXNlciIsImF1dGhlbnRpY2F0aW9uX3R5cGUiOiJiZWFyZXIifSwiYXVkIjoiaWItY3RrIiwiZXhwIjoxNjMzNTM1OTU5LCJqdGkiOiJhMmE4NmU0YS1kYWU1LTQ4MWYtYmFjMy02Y2VjMDAxM2RiMjYiLCJpYXQiOjE2MzM1Mjg4MDQsImlzcyI6ImlkZW50aXR5IiwibmJmIjoxNjMzNTI4ODA0fQ.redacted",
				RequestID:   "6c9a32b2-57f3-40c0-a4d3-1b22a8e15f16",
				DecisionInput: DecisionInput{
					Type:             "",
					Verb:             "",
					SealCtx:          nil,
					DecisionDocument: "",
				},
			},
			wantRes: ResultMap{
				"allow":       false,
				"obligations": EmptyObj{},
			},

			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := a.Authorize(tt.ctx, tt.cfg, tt.input)

			// TODO
			var resMap ResultMap
			if err == nil {
				resMap, err = parseResult(tt.ctx, res)
			}

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
			t.Logf("Result map: %+v", resMap)

			resJSON, err := json.MarshalIndent(resMap, "", "    ")
			if err != nil {
				t.Errorf("JSON marshal error %v", err)
				return
			}

			wantResJSON, err := json.MarshalIndent(tt.wantRes, "", "    ")
			if err != nil {
				t.Errorf("JSON marshal error %v", err)
				return
			}

			if !reflect.DeepEqual(resJSON, wantResJSON) {
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
