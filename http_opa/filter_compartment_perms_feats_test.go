package httpopa

import (
	"context"
	"io/ioutil"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/v2/utils_test"
	atlas_claims "github.com/infobloxopen/atlas-claims"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

func TestFilterCompartmentPermissionsOpa(t *testing.T) {
	stdLoggr := logrus.StandardLogger()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	done := make(chan struct{})
	clienter := utils_test.StartOpa(ctx, t, done)
	cli, ok := clienter.(*opa_client.Client)
	if !ok {
		t.Fatal("Unable to convert interface to (*Client)")
		return
	}

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	policyRego, err := ioutil.ReadFile("testdata/mock_authz_policy.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "mock_authz_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	auther := NewHttpAuthorizer("bogus_unused_application_value",
		WithOpaClienter(cli),
	)

	testCases := []struct {
		name   string
		cptId  string
		inpVal []string
		expVal []string
	}{
		{
			name:   "empty-compartment",
			cptId:  "",
			inpVal: []string{"user-view", "tag-read"},
			expVal: []string{"user-view", "tag-read"},
		},
		{
			name:   "root-compartment",
			cptId:  ".",
			inpVal: []string{"user-view", "tag-read"},
			expVal: []string{"user-view", "tag-read"},
		},
		{
			name:   "non-root-compartment",
			cptId:  "green.",
			inpVal: []string{"user-view", "tag-read"},
			expVal: []string{"filtered-perm-a", "filtered-perm-b"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			claims := &atlas_claims.Claims{
				CompartmentID: tt.cptId,
			}

			jwt, err := atlas_claims.BuildJwt(claims, "some-hmac-key-we-dont-care", time.Hour*9)
			if err != nil {
				t.Fatalf("FAIL: BuildJwt() unexpected err=%v", err)
			}

			ttCtx := utils_test.ContextWithJWT(ctx, jwt)

			gotVal, err := auther.FilterCompartmentPermissions(ttCtx, tt.inpVal)
			if err != nil {
				t.Errorf("FAIL: FilterCompartmentPermissions() unexpected err=%v", err)
			}

			sort.Strings(gotVal)
			//t.Logf("gotVal=%#v", gotVal)

			sort.Strings(tt.expVal)
			if !reflect.DeepEqual([]string(gotVal), tt.expVal) {
				t.Errorf("FAIL:\ngotVal:  %#v\nexpVal: %#v",
					gotVal, tt.expVal)
			}
		})
	}
}

func TestFilterCompartmentPermissionsMockOpaClient(t *testing.T) {
	testCases := []struct {
		name     string
		respJson string
		expErr   bool
		expVal   []string
	}{
		{
			name:     `valid result`,
			respJson: `{ "result": [ "red.", "green.", "blue." ] }`,
			expErr:   false,
			expVal:   []string{"red.", "green.", "blue."},
		},
		{
			name:     `null result ok`,
			respJson: `{ "result": null }`,
			expErr:   false,
			expVal:   nil,
		},
		{
			name:     `empty result ok`,
			respJson: `{ "result": [] }`,
			expErr:   false,
			expVal:   []string{},
		},
		{
			name:     `incorrect result type`,
			respJson: `[ null ]`,
			expErr:   true,
			expVal:   nil,
		},
		{
			name:     `no result key`,
			respJson: `{ "rresult": null }`,
			expErr:   false,
			expVal:   nil,
		},
		{
			name:     `invalid result object`,
			respJson: `{ "result": { "one": 1, "two": 2 } }`,
			expErr:   true,
			expVal:   nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			mockOpaClienter := utils_test.MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tt.respJson,
			}
			auther := NewHttpAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			claims := &atlas_claims.Claims{}
			jwt, err := atlas_claims.BuildJwt(claims, "some-hmac-key-we-dont-care", time.Hour*9)
			if err != nil {
				t.Fatalf("FAIL: BuildJwt() unexpected err=%v", err)
			}
			ttCtx := utils_test.ContextWithJWT(ctx, jwt)

			gotVal, gotErr := auther.FilterCompartmentPermissions(ttCtx, nil)
			//t.Logf("gotErr=%#v, gotVal=%#v", gotVal, gotErr)

			if tt.expErr && gotErr == nil {
				t.Errorf("FAIL: expected err, but got no err")
			} else if !tt.expErr && gotErr != nil {
				t.Errorf("FAIL: got unexpected err=%s", gotErr)
			}

			if gotErr != nil && gotVal != nil {
				t.Errorf("FAIL: returned val should be nil if err returned")
			}

			if !reflect.DeepEqual([]string(gotVal), tt.expVal) {
				t.Errorf("FAIL: expVal=%#v gotVal=%#v",
					tt.expVal, gotVal)
			}
		})
	}
}

func TestFilterCompartmentFeaturesOpa(t *testing.T) {
	stdLoggr := logrus.StandardLogger()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	done := make(chan struct{})
	clienter := utils_test.StartOpa(ctx, t, done)
	cli, ok := clienter.(*opa_client.Client)
	if !ok {
		t.Fatal("Unable to convert interface to (*Client)")
		return
	}

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	policyRego, err := ioutil.ReadFile("testdata/mock_authz_policy.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "mock_authz_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	auther := NewHttpAuthorizer("bogus_unused_application_value",
		WithOpaClienter(cli),
	)

	testCases := []struct {
		name   string
		cptId  string
		inpVal map[string][]string
		expVal map[string][]string
	}{
		{
			name:   "empty-compartment",
			cptId:  "",
			inpVal: map[string][]string{"ddi": {"dhcp", "ipam"}, "ui": {"anycast"}},
			expVal: map[string][]string{"ddi": {"dhcp", "ipam"}, "ui": {"anycast"}},
		},
		{
			name:   "root-compartment",
			cptId:  ".",
			inpVal: map[string][]string{"ddi": {"dhcp", "ipam"}, "ui": {"anycast"}},
			expVal: map[string][]string{"ddi": {"dhcp", "ipam"}, "ui": {"anycast"}},
		},
		{
			name:   "non-root-compartment",
			cptId:  "green.",
			inpVal: map[string][]string{"ddi": {"dhcp", "ipam"}, "ui": {"anycast"}},
			expVal: map[string][]string{
				"filtered-app-a": {"filtered-app-a-feat-a", "filtered-app-a-feat-b"},
				"filtered-app-b": {"filtered-app-b-feat-a"},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			claims := &atlas_claims.Claims{
				CompartmentID: tt.cptId,
			}

			jwt, err := atlas_claims.BuildJwt(claims, "some-hmac-key-we-dont-care", time.Hour*9)
			if err != nil {
				t.Fatalf("FAIL: BuildJwt() unexpected err=%v", err)
			}

			ttCtx := utils_test.ContextWithJWT(ctx, jwt)

			gotVal, err := auther.FilterCompartmentFeatures(ttCtx, tt.inpVal)
			if err != nil {
				t.Errorf("FAIL: FilterCompartmentFeatures() unexpected err=%v", err)
			}

			//sort.Strings(gotVal)
			//t.Logf("gotVal=%#v", gotVal)

			//sort.Strings(tt.expVal)
			if !reflect.DeepEqual(map[string][]string(gotVal), tt.expVal) {
				t.Errorf("FAIL:\ngotVal:  %#v\nexpVal: %#v",
					gotVal, tt.expVal)
			}
		})
	}
}

func TestFilterCompartmentFeaturesMockOpaClient(t *testing.T) {
	testCases := []struct {
		name     string
		respJson string
		expErr   bool
		expVal   map[string][]string
	}{
		{
			name:     `valid result`,
			respJson: `{ "result": { "app": [ "feat-a", "feat-b" ] } }`,
			expErr:   false,
			expVal:   map[string][]string{"app": {"feat-a", "feat-b"}},
		},
		{
			name:     `null result ok`,
			respJson: `{ "result": null }`,
			expErr:   false,
			expVal:   nil,
		},
		{
			name:     `empty result ok`,
			respJson: `{ "result": {} }`,
			expErr:   false,
			expVal:   map[string][]string{},
		},
		{
			name:     `null features ok`,
			respJson: `{ "result": { "app": null } }`,
			expErr:   false,
			expVal:   map[string][]string{"app": nil},
		},
		{
			name:     `empty features ok`,
			respJson: `{ "result": { "app": [] } }`,
			expErr:   false,
			expVal:   map[string][]string{"app": {}},
		},
		{
			name:     `incorrect result type`,
			respJson: `[ null ]`,
			expErr:   true,
			expVal:   nil,
		},
		{
			name:     `no result key`,
			respJson: `{ "rresult": null }`,
			expErr:   false,
			expVal:   nil,
		},
		{
			name:     `invalid result object`,
			respJson: `{ "result": [ "one", "two" ] }`,
			expErr:   true,
			expVal:   nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			mockOpaClienter := utils_test.MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tt.respJson,
			}
			auther := NewHttpAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			claims := &atlas_claims.Claims{}
			jwt, err := atlas_claims.BuildJwt(claims, "some-hmac-key-we-dont-care", time.Hour*9)
			if err != nil {
				t.Fatalf("FAIL: BuildJwt() unexpected err=%v", err)
			}
			ttCtx := utils_test.ContextWithJWT(ctx, jwt)

			gotVal, gotErr := auther.FilterCompartmentFeatures(ttCtx, nil)
			//t.Logf("gotErr=%#v, gotVal=%#v", gotVal, gotErr)

			if tt.expErr && gotErr == nil {
				t.Errorf("FAIL: expected err, but got no err")
			} else if !tt.expErr && gotErr != nil {
				t.Errorf("FAIL: got unexpected err=%s", gotErr)
			}

			if gotErr != nil && gotVal != nil {
				t.Errorf("FAIL: returned val should be nil if err returned")
			}

			if !reflect.DeepEqual(map[string][]string(gotVal), tt.expVal) {
				t.Errorf("FAIL: expVal=%#v gotVal=%#v",
					tt.expVal, gotVal)
			}
		})
	}
}
