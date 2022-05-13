package wasm

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

	"github.com/infobloxopen/atlas-authz-middleware/utils"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
	"github.com/sirupsen/logrus"
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

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	opaCfg := OPAConfigValues{
		address: svr.URL,
		resource:            "/bundles/bundle.tar.gz",
		defaultDecisionPath: DefaultDecisionPath,
		persistBundle:       false,
		persistDir:          "",
	}

	cfg := &Config{
		decisionPath:         DefaultDecisionPath,
		opaConfigFile:        createOPAConfigFile(opaCfg, logger),
		decisionInputHandler: new(DefaultDecisionInputer),
		claimsVerifier:       utils.UnverifiedClaimFromBearers,
		entitledServices:     nil,
		acctEntitlementsApi:  DefaultAcctEntitlementsApiPath,
	}

	a, err := NewAutorizer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ctx        context.Context
		cfg        *Config
		fullMethod string
		wantRes    ResultMap
		wantErr    bool
	}{
		{
			name: "AllowOk",
			ctx: utils_test.BuildCtx(t,
				utils_test.WithLogger(logger),
				utils_test.WithRequestID("request-1"),
				utils_test.WithJWTAccountID("1073"),
				utils_test.WithJWTIdentityAccountID("a2db41ad-3830-495d-ba07-000000001073"),
				utils_test.WithJWTGroups("act_admin",
					"user",
					"ib-access-control-admin",
					"ib-td-admin",
					"rb-group-test-0011",
					"bootstrap-test-group",
					"ib-ddi-admin",
					"ib-interactive-user"),
				utils_test.WithJWTAudience("ib-ctk")),
			cfg: func() *Config {
				cfg.applicaton = "atlas.tagging"
				cfg.decisionPath = DefaultDecisionPath
				return cfg
			}(),
			fullMethod: "/service.TagService/List",
			wantRes: ResultMap{
				"allow": true,
				"obligations": map[string]interface{}{
					"authz.rbac.entitlement": EmptyObj{},
					"authz.rbac.rbac":        EmptyObj{},
				},
				"request_id": "request-1",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err1 := composeInput(tt.ctx, tt.cfg, tt.fullMethod, nil)
			t.Logf("Composed input: %+v", func() string {
				bs, _ := json.MarshalIndent(input, "", "  ")
				return string(bs)
			}())

			result, err2 := a.Authorize(tt.ctx, input)
			t.Logf("OPA result: %+v", func() string {
				bs, _ := json.MarshalIndent(result, "", "  ")
				return string(bs)
			}())

			resMap, err3 := parseResult(tt.ctx, result)
			t.Logf("Parsed result map: %+v", func() string {
				bs, _ := json.MarshalIndent(resMap, "", "  ")
				return string(bs)
			}())

			var err error
			switch {
			case err1 != nil:
				err = err1
			case err2 != nil:
				err = err2
			case err3 != nil:
				err = err3
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
