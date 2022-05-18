package opasdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/sdk"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/infobloxopen/atlas-authz-middleware/utils"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
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

type AuthorizeStruct struct {
	name       string
	ctx        context.Context
	cfg        *Config
	fullMethod string
	wantRes    ResultMap
	wantErr    bool
}

var result interface{}

// sdk % go test -bench=Autorizer_Authorize -benchtime=10s -run=dontrunanytests -benchmem
//ToDo: Benchmark parallel executions
func BenchmarkAutorizer_Authorize(b *testing.B) {
	cfg := &Config{
		applicaton:           "TODO",
		decisionInputHandler: new(DefaultDecisionInputer),
		claimsVerifier:       utils.UnverifiedClaimFromBearers,
		entitledServices:     nil,
		acctEntitlementsApi:  DefaultAcctEntitlementsApiPath,
		logger:               logrus.New(),
		opaConfig: opaConfig{
			decisionPath:        "TODO",
			defaultDecisionPath: DefaultDecisionPath,
			bundleResourcePath:  "TODO",
			serviceURL:          "TODO",
			serviceCredToken:    "",
			persistBundle:       false,
			persistDir:          "",
			opaConfigBuf:        nil,
			pollingMinDelaySeconds:    60,
			pollingMaxDelaySeconds:    120,
			pollingLongTimeoutSeconds: 10,
			bundleReloadInterval:      time.Minute,
		},
	}

	dataTestDir, err := filepath.Abs("./data_test")
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("Absolute path: %s", dataTestDir)

	cfg.serviceURL = ""
	cfg.bundleResourcePath = "file://" + dataTestDir + "/bundle.tar.gz"

	cfg.logger.SetLevel(logrus.DebugLevel)
	cfg.opaConfigBuf = createOPAConfigBuf(&cfg.opaConfig, cfg.logger)

	a, err := NewAutorizer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	tt := struct {
		name       string
		ctx        context.Context
		cfg        *Config
		fullMethod string
		wantRes    ResultMap
		wantErr    bool
	}{
		name: "AuthzOk",
		ctx: utils_test.BuildCtx(cfg.logger,
			utils_test.WithLogger(true),
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
			utils_test.WithJWTAudience("ib-ctk"),
			utils_test.WithExpirationDate(time.Now().Add(10*time.Minute))),
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
	}

	var res interface{}
	input, _ := composeInput(tt.ctx, tt.cfg, tt.fullMethod, nil)
	for i := 0; i < b.N; i++ {
		res, _ = a.Authorize(tt.ctx, input)
	}
	result = res
}

func Test_autorizer_Authorize(t *testing.T) {
	const (
		_ = iota
		Server
		File
	)

	with := File
	cfg := &Config{
		applicaton:           "TODO",
		decisionInputHandler: new(DefaultDecisionInputer),
		claimsVerifier:       utils.UnverifiedClaimFromBearers,
		entitledServices:     nil,
		acctEntitlementsApi:  DefaultAcctEntitlementsApiPath,
		logger:               logrus.New(),
		opaConfig: opaConfig{
			decisionPath:              "TODO",
			defaultDecisionPath:       DefaultDecisionPath,
			bundleResourcePath:        "TODO",
			serviceURL:                "TODO",
			serviceCredToken:          "",
			persistBundle:             false,
			persistDir:                "",
			opaConfigBuf:              nil,
			pollingMinDelaySeconds:    60,
			pollingMaxDelaySeconds:    120,
			pollingLongTimeoutSeconds: 10,
			bundleReloadInterval:      time.Minute,
		},
	}

	switch with {
	case Server:
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

		cfg.serviceURL = svr.URL
		cfg.bundleResourcePath = "/bundles/bundle.tar.gz"
	case File:
		dataTestDir, err := filepath.Abs("./data_test")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Absolute path: %s", dataTestDir)

		cfg.serviceURL = ""
		cfg.bundleResourcePath = "file://" + dataTestDir + "/bundle.tar.gz"
	}

	cfg.logger.SetLevel(logrus.DebugLevel)
	cfg.opaConfigBuf = createOPAConfigBuf(&cfg.opaConfig, cfg.logger)

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
			name: "AuthzOk",
			ctx: utils_test.BuildCtx(cfg.logger,
				utils_test.WithLogger(true),
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
				utils_test.WithJWTAudience("ib-ctk"),
				utils_test.WithExpirationDate(time.Now().Add(time.Minute))),
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

			_, resMap, err3 := parseResult(tt.ctx, result)
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

// Bundle reconfiguration triggers bundle reload.
// Put two bundles into ../data_test/bundles
// bundle.tar.gz - allows authorization
// new.bundle.tar.gz - disallows
func Test_reconfig_bundle(t *testing.T) {
	const (
		_ = iota
		Server
		File
	)

	with := File
	triggerFlag := false
	cfg := &Config{
		applicaton:           "TODO",
		decisionInputHandler: new(DefaultDecisionInputer),
		claimsVerifier:       utils.UnverifiedClaimFromBearers,
		entitledServices:     nil,
		acctEntitlementsApi:  DefaultAcctEntitlementsApiPath,
		logger:               logrus.New(),
		opaConfig: opaConfig{
			decisionPath:              "TODO",
			defaultDecisionPath:       DefaultDecisionPath,
			bundleResourcePath:        "TODO",
			serviceURL:                "TODO",
			serviceCredToken:          "",
			persistBundle:             false,
			persistDir:                "",
			opaConfigBuf:              nil,
			pollingMinDelaySeconds:    60,
			pollingMaxDelaySeconds:    120,
			pollingLongTimeoutSeconds: 10,
			bundleReloadInterval:      time.Minute,
		},
	}

	switch with {
	case Server:
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

		cfg.serviceURL = svr.URL
		cfg.bundleResourcePath = "/bundles/bundle.tar.gz"
	case File:
		dataTestDir, err := filepath.Abs("./data_test")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Absolute path: %s", dataTestDir)

		cfg.serviceURL = ""
		cfg.bundleResourcePath = "file://" + dataTestDir + "/bundle.tar.gz"
	}

	cfg.logger.SetLevel(logrus.DebugLevel)
	cfg.opaConfigBuf = createOPAConfigBuf(&cfg.opaConfig, cfg.logger)

	a, err := NewAutorizer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ctx        context.Context
		cfg        *Config
		fullMethod string
		wantRes1   ResultMap
		wantRes2   ResultMap
		wantErr    bool
	}{
		{
			name: "Reload bundle test",
			ctx: utils_test.BuildCtx(cfg.logger,
				utils_test.WithLogger(true),
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
			wantRes1: ResultMap{
				"allow": true,
				"obligations": map[string]interface{}{
					"authz.rbac.entitlement": EmptyObj{},
					"authz.rbac.rbac":        EmptyObj{},
				},
				"request_id": "request-1",
			},
			wantRes2: ResultMap{
				"allow": false,
				"obligations": map[string]interface{}{
					"authz.rbac.entitlement": EmptyObj{},
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

			_, resMap, err3 := parseResult(tt.ctx, result)
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

			wantResJSON, err := json.MarshalIndent(tt.wantRes1, "", "    ")
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

			dataTestDir, err := filepath.Abs("./data_test")
			bundleFile := dataTestDir + "/bundles/bundle.tar.gz"
			newBundleFile := dataTestDir + "/bundles/new.bundle.tar.gz"
			// copy new bundle tarball
			CopyFile(newBundleFile, dataTestDir+"/bundle.tar.gz")
			// reconfigure opa instance to trigger bundle reload
			// change cfg.opaConfig.pollingMinDelaySeconds to trigger config update
			readyChan := make(chan struct{})
			if triggerFlag {
				cfg.opaConfig.pollingMinDelaySeconds = cfg.opaConfig.pollingMinDelaySeconds - 1
			} else {
				cfg.opaConfig.pollingMinDelaySeconds = cfg.opaConfig.pollingMinDelaySeconds + 1
			}

			a.engine.Configure(context.TODO(), sdk.ConfigOptions{
				Config: createOPAConfigBuf(&cfg.opaConfig, cfg.logger),
				Ready:  readyChan,
			})
			// sleep 2 sec, need time to apply new bundle
			time.Sleep(time.Second * 2)
			result, err2 = a.Authorize(tt.ctx, input)
			t.Logf("OPA result: %+v", func() string {
				bs, _ := json.MarshalIndent(result, "", "  ")
				return string(bs)
			}())

			_, resMap, err3 = parseResult(tt.ctx, result)
			t.Logf("Parsed result map: %+v", func() string {
				bs, _ := json.MarshalIndent(resMap, "", "  ")
				return string(bs)
			}())

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
			resJSON, err = json.MarshalIndent(resMap, "", "    ")
			if err != nil {
				t.Errorf("JSON marshal error %v", err)
				return
			}

			wantResJSON, err = json.MarshalIndent(tt.wantRes2, "", "    ")
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
			// restore old bundle
			CopyFile(bundleFile, dataTestDir+"/bundle.tar.gz")

			t.Logf("\t%s %s test is passed", succeed, tt.name)
		})
	}
}

func CopyFile(src, dest string) {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(dest, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dest)
		fmt.Println(err)
		return
	}
}
