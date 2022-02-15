package grpc_opa_middleware

import (
	"context"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

func TestGetAcctEntitlementsOpaRaw(t *testing.T) {
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

	auther := NewDefaultAuthorizer("bogus_unused_application_value",
		WithOpaClienter(cli),
	)

	rawBytes, err := auther.GetAcctEntitlementsRaw(ctx)
	t.Logf("rawBytes=%s", string(rawBytes))

	expected := `{"result":{"2001016":{"environment":["ac","heated-seats"],"wheel":["abs","alloy","tpms"]},"2001040":{"environment":["ac","side-mirror-defogger"],"powertrain":["automatic","turbo"]}}}`

	if string(rawBytes) != expected {
		t.Errorf("\ngot:  %s\nwant: %s", string(rawBytes), expected)
	}
}

func TestGetAcctEntitlementsMockOpaClient(t *testing.T) {
	testMap := []struct {
		name         string
		regoRespJSON string
		expectErr    bool
		expectedVal  *AcctEntitlementsType
	}{
		{
			name: `valid result`,
			regoRespJSON: `{ "result": {
				"acct1": { "svc1a": [ "feat1a1", "feat1a2" ] },
				"acct2": { "svc2a": [ "feat2a1", "feat2a2" ],
				       "svc2b": [ "feat2b1", "feat2b2" ] }
			}}`,
			expectErr: false,
			expectedVal: &AcctEntitlementsType{
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
			expectedVal: &AcctEntitlementsType{
				"acct1": {"svc1a": {"feat1a1", "feat1a2"}},
			},
		},
		{
			name: `null service entitled features ok`,
			regoRespJSON: `{ "result": {
				"acct2": { "svc2a": null,
				       "svc2b": [ "feat2b1", "feat2b2" ] }
			}}`,
			expectErr: false,
			expectedVal: &AcctEntitlementsType{
				"acct2": {"svc2b": {"feat2b1", "feat2b2"}},
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
			expectErr:    true,
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
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoRespJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetAcctEntitlements(ctx)
		t.Logf("%d: %q: actualErr=%#v, actualVal=%#v", nth, tm.name, actualVal, actualErr)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualVal != nil {
			t.Errorf("%d: %q: returned val should be nil if err returned", nth, tm.name)
		}

		if !reflect.DeepEqual(actualVal, tm.expectedVal) {
			t.Errorf("%d: %q: expectedVal=%#v actualVal=%#v",
				nth, tm.name, tm.expectedVal, actualVal)
		}
	}
}
