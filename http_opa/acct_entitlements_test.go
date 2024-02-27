package httpopa

import (
	"context"
	"io/ioutil"
	"reflect"
	"testing"

	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/v2/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

func TestGetAcctEntitlementsOpa(t *testing.T) {
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

	actualSpecific, err := auther.GetAcctEntitlements(ctx,
		[]string{"2001040", "2001230"}, []string{"powertrain", "wheel"})
	if err != nil {
		t.Errorf("FAIL: GetAcctEntitlements() unexpected err=%v", err)
	}
	t.Logf("actualSpecific=%#v", actualSpecific)

	expectSpecific := &az.AcctEntitlementsType{
		"2001040": {
			"powertrain": {"automatic", "turbo"},
		},
		"2001230": {
			"powertrain": {"manual", "v8"},
			"wheel":      {"run-flat"},
		},
	}
	if !reflect.DeepEqual(actualSpecific, expectSpecific) {
		t.Errorf("FAIL:\nactualSpecific:  %#v\nexpectSpecific: %#v",
			actualSpecific, expectSpecific)
	}
}

func TestGetAcctEntitlementsMockOpaClient(t *testing.T) {
	testMap := []struct {
		name         string
		regoRespJSON string
		expectErr    bool
		expectedVal  *az.AcctEntitlementsType
	}{
		{
			name: `valid result`,
			regoRespJSON: `{ "result": {
				"acct1": { "svc1a": [ "feat1a1", "feat1a2" ] },
				"acct2": { "svc2a": [ "feat2a1", "feat2a2" ],
				       "svc2b": [ "feat2b1", "feat2b2" ] }
			}}`,
			expectErr: false,
			expectedVal: &az.AcctEntitlementsType{
				"acct1": {"svc1a": {"feat1a1", "feat1a2"}},
				"acct2": {"svc2a": {"feat2a1", "feat2a2"},
					"svc2b": {"feat2b1", "feat2b2"}},
			},
		},
		{
			name:         `null result ok`,
			regoRespJSON: `{ "result": null }`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name: `null account entitled service ok`,
			regoRespJSON: `{ "result": {
				"acct1": { "svc1a": [ "feat1a1", "feat1a2" ] },
				"acct2": null
			}}`,
			expectErr: false,
			expectedVal: &az.AcctEntitlementsType{
				"acct1": {"svc1a": {"feat1a1", "feat1a2"}},
				"acct2": nil,
			},
		},
		{
			name: `null service entitled features ok`,
			regoRespJSON: `{ "result": {
				"acct2": { "svc2a": null,
				       "svc2b": [ "feat2b1", "feat2b2" ] }
			}}`,
			expectErr: false,
			expectedVal: &az.AcctEntitlementsType{
				"acct2": {"svc2a": nil,
					"svc2b": {"feat2b1", "feat2b2"}},
			},
		},
		{
			name:         `incorrect result type`,
			regoRespJSON: `[ null ]`,
			expectErr:    true,
			expectedVal:  nil,
		},
		{
			name:         `no result key`,
			regoRespJSON: `{ "rresult": null }`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         `invalid result array`,
			regoRespJSON: `{ "result": [ 1, 2 ] }`,
			expectErr:    true,
			expectedVal:  nil,
		},
		{
			name: `invalid account entitled service`,
			regoRespJSON: `{ "result": {
				"acct2": { "svc2a": [ "feat2a1", "feat2a2" ],
				       "svc2b": {} }
			}}`,
			expectErr:   true,
			expectedVal: nil,
		},
		{
			name: `invalid service entitled feature`,
			regoRespJSON: `{ "result": {
				"acct2": { "svc2a": [ "feat2a1", "feat2a2" ],
				       "svc2b": [ "feat2b1", 31415926 ] }
			}}`,
			expectErr:   true,
			expectedVal: nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for nth, tm := range testMap {
		mockOpaClienter := utils_test.MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoRespJSON,
		}
		auther := NewHttpAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetAcctEntitlements(ctx, nil, nil)
		t.Logf("%d: %q: actualErr=%#v, actualVal=%#v", nth, tm.name, actualVal, actualErr)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualVal != nil {
			t.Errorf("%d: %q: FAIL: returned val should be nil if err returned", nth, tm.name)
		}

		if !reflect.DeepEqual(actualVal, tm.expectedVal) {
			t.Errorf("%d: %q: FAIL: expectedVal=%#v actualVal=%#v",
				nth, tm.name, tm.expectedVal, actualVal)
		}
	}
}
