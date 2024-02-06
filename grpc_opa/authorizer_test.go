package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/v2/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/v2/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/opautil"
	logrus "github.com/sirupsen/logrus"
	logrustesthook "github.com/sirupsen/logrus/hooks/test"
)

func TestRedactJWT(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	if redacted := opautil.RedactJWT(token); !strings.HasSuffix(redacted, az.REDACTED) {

		t.Errorf("got: %s, wanted: %s", redacted, az.REDACTED)
	}
}

func Test_parseEndpoint(t *testing.T) {
	tests := []struct {
		fullMethod string
		endpoint   string
	}{
		{
			fullMethod: "/service.TagService/ListRetiredTags",
			endpoint:   "TagService.ListRetiredTags",
		},
		{
			fullMethod: "/TagService/ListRetiredTags",
			endpoint:   ".TagService.ListRetiredTags",
		},
		{
			fullMethod: ".TagService.ListRetiredTags",
			endpoint:   "ListRetiredTags",
		},
		{
			fullMethod: "TagService/ListRetiredTags",
			endpoint:   "TagService.ListRetiredTags",
		},
		{
			fullMethod: "TagService.ListRetiredTags",
			endpoint:   "ListRetiredTags",
		},
		{
			fullMethod: "/ListRetiredTags",
			endpoint:   ".ListRetiredTags",
		},
		{
			fullMethod: ".ListRetiredTags",
			endpoint:   "ListRetiredTags",
		},
		{
			fullMethod: "ListRetiredTags",
			endpoint:   "ListRetiredTags",
		},
	}

	for _, tst := range tests {
		gotEndpoint := parseEndpoint(tst.fullMethod)
		if gotEndpoint != tst.endpoint {
			t.Errorf("parseEndpoint(%s)='%s', wanted='%s'",
				tst.fullMethod, gotEndpoint, tst.endpoint)
		}
	}
}

func TestAffirmAuthorizationOpa(t *testing.T) {
	testMap := []struct {
		name        string
		application string
		fullMethod  string
		expectErr   bool
	}{
		{
			name:        "permitted",
			application: "automobile",
			fullMethod:  "/service.Vehicle/StompGasPedal",
			expectErr:   false,
		},
		{
			name:        "denied, incorrect application",
			application: "train",
			fullMethod:  "/service.Vehicle/StompGasPedal",
			expectErr:   true,
		},
		{
			name:        "denied, incorrect endpoint",
			application: "automobile",
			fullMethod:  "/service.Vehicle/SteerLeft",
			expectErr:   true,
		},
	}

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

	policyRego, err := ioutil.ReadFile("testdata/mock_system_main.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "mock_system_main_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	// DecisionInputHandler with explicitly set decision document
	var decInputr MockDecisionInputr
	decInputr.DecisionInput.DecisionDocument = "v1/data/system/main"

	for nth, tm := range testMap {
		// Test without explicitly set decision document
		authzr := NewDefaultAuthorizer(tm.application,
			WithOpaClienter(cli),
			WithClaimsVerifier(commonClaim.NullClaimsVerifier),
		)

		_, actualErr := authzr.AffirmAuthorization(ctx, tm.fullMethod, nil)
		if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %s: AffirmAuthorization(explicit) FAIL: unexpected DENY, err=%#v", nth, tm.name, err)
		} else if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %s: AffirmAuthorization(explicit) FAIL: unexpected PERMIT", nth, tm.name)
		}

		// Test with explicitly set decision document
		authzr = NewDefaultAuthorizer(tm.application,
			WithOpaClienter(cli),
			WithDecisionInputHandler(&decInputr),
			WithClaimsVerifier(commonClaim.NullClaimsVerifier),
		)

		_, actualErr = authzr.AffirmAuthorization(ctx, tm.fullMethod, nil)
		if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %s: AffirmAuthorization(explicit) FAIL: unexpected DENY, err=%#v", nth, tm.name, err)
		} else if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %s: AffirmAuthorization(explicit) FAIL: unexpected PERMIT", nth, tm.name)
		}
	}
}

func TestAffirmAuthorizationMockOpaEvaluator(t *testing.T) {
	ErrBoom := errors.New("boom")

	testMap := []struct {
		name        string
		opaEvaltor  az.OpaEvaluator
		expectCtx   bool
		expectedErr error
	}{
		{
			name: "authz permitted, nil opa error",
			opaEvaltor: func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
				respJSON := fmt.Sprintf(`{"allow": %s}`, "true")
				json.Unmarshal([]byte(respJSON), opaResp)
				return nil
			},
			expectCtx:   true,
			expectedErr: nil,
		},
		{
			name: "authz denied, nil opa error",
			opaEvaltor: func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
				respJSON := fmt.Sprintf(`{"allow": %s}`, "false")
				json.Unmarshal([]byte(respJSON), opaResp)
				return nil
			},
			expectCtx:   false,
			expectedErr: ErrForbidden,
		},
		{
			name: "bogus opa response, nil opa error",
			opaEvaltor: func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
				respJSON := fmt.Sprintf(`{"bogus_opa_response_field": %s}`, "true")
				json.Unmarshal([]byte(respJSON), opaResp)
				return nil
			},
			expectCtx:   false,
			expectedErr: ErrForbidden,
		},
		{
			name: "opa error",
			opaEvaltor: func(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
				respJSON := fmt.Sprintf(`{"allow": %s}`, "true")
				json.Unmarshal([]byte(respJSON), opaResp)
				return ErrBoom
			},
			expectCtx:   false,
			expectedErr: ErrBoom,
		},
	}

	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(logrus.StandardLogger()))

	for nth, tm := range testMap {
		auther := NewDefaultAuthorizer("app",
			WithOpaEvaluator(tm.opaEvaltor),
			WithClaimsVerifier(commonClaim.NullClaimsVerifier),
		)

		resultCtx, resultErr := auther.AffirmAuthorization(ctx, "FakeMethod", nil)
		if resultErr != tm.expectedErr {
			t.Errorf("%d: %q: got error: %s, wanted error: %s", nth, tm.name, resultErr, tm.expectedErr)
		}
		if resultErr == nil && resultCtx == nil {
			t.Errorf("%d: %q: returned ctx should not be nil if no err returned", nth, tm.name)
		}
		if resultErr != nil && resultCtx != nil {
			t.Errorf("%d: %q: returned ctx should be nil if err returned", nth, tm.name)
		}
	}
}

func TestDebugLogging(t *testing.T) {
	testMap := []struct {
		name         string
		regoRespJSON string
		expectErr    bool
		qryLogLvl    logrus.Level
		qryLogMsg    string
		qryOpaResp   string
		evalLogLvl   logrus.Level
		evalLogMsg   string
		evalOpaResp  string
	}{
		{
			name:         `valid rego object and valid response json object`,
			regoRespJSON: `{"allow": true, "obligations": {"policy1": {}}}`,
			expectErr:    false,
			qryLogLvl:    logrus.DebugLevel,
			qryLogMsg:    `opa_policy_engine_response`,
			qryOpaResp:   `&map[allow:true obligations:map[policy1:map[]]]`,
			evalLogLvl:   logrus.DebugLevel,
			evalLogMsg:   `authorization_result`,
			evalOpaResp:  `map[allow:true obligations:map[policy1:map[]]]`,
		},
		{
			name:         `valid rego set but invalid json set`,
			regoRespJSON: `{"allow": true, "obligations": {"policy1", "policy2"}}`,
			expectErr:    true,
			qryLogLvl:    logrus.ErrorLevel,
			qryLogMsg:    `opa_policy_engine_request_error`,
			qryOpaResp:   ``,
			evalLogLvl:   logrus.DebugLevel,
			evalLogMsg:   `authorization_result`,
			evalOpaResp:  `map[]`,
		},
		{
			name:         `valid rego array and valid response json array`,
			regoRespJSON: `{"allow": true, "obligations": []}`,
			expectErr:    false,
			qryLogLvl:    logrus.DebugLevel,
			qryLogMsg:    `opa_policy_engine_response`,
			qryOpaResp:   `&map[allow:true obligations:[]]`,
			evalLogLvl:   logrus.DebugLevel,
			evalLogMsg:   `authorization_result`,
			evalOpaResp:  `map[allow:true obligations:[]]`,
		},
	}

	loggertesthook := logrustesthook.NewGlobal()
	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoRespJSON,
		}
		auther := NewDefaultAuthorizer("app",
			WithOpaClienter(&mockOpaClienter),
			WithClaimsVerifier(commonClaim.NullClaimsVerifier),
		)
		loggertesthook.Reset()

		_, resultErr := auther.AffirmAuthorization(ctx, "FakeMethod", nil)
		if !tm.expectErr && resultErr != nil {
			t.Errorf("%d: %q: got unexpected error: %s", nth, tm.name, resultErr)
		}
		if tm.expectErr && resultErr == nil {
			t.Errorf("%d: %q: expected error, but got no error", nth, tm.name)
		}

		gotOpaQryLogMsg := false
		gotOpaEvalLogMsg := false
		for eth, entry := range loggertesthook.AllEntries() {
			t.Logf("%d: %q: [%d]logrus.Entry.Level: %s", nth, tm.name, eth, entry.Level)
			t.Logf("%d: %q: [%d]logrus.Entry.Message: %s", nth, tm.name, eth, entry.Message)
			t.Logf("%d: %q: [%d]logrus.Entry.Data: %s", nth, tm.name, eth, entry.Data)

			opaResp, gotOpaResp := entry.Data["opaResp"]
			entryOpaRespStr := fmt.Sprint(opaResp)
			if gotOpaResp {
				t.Logf("%d: %q: [%d]logrus.Entry.Data[opaResp]: %s", nth, tm.name, eth, entryOpaRespStr)
			}

			if entry.Level == tm.qryLogLvl && entry.Message == tm.qryLogMsg {
				gotOpaQryLogMsg = true
				if len(tm.qryOpaResp) > 0 && gotOpaResp && entryOpaRespStr != tm.qryOpaResp {
					gotOpaQryLogMsg = false
				}
				continue
			}

			if entry.Level == tm.evalLogLvl && entry.Message == tm.evalLogMsg {
				gotOpaEvalLogMsg = true
				if len(tm.evalOpaResp) > 0 && gotOpaResp && entryOpaRespStr != tm.evalOpaResp {
					gotOpaEvalLogMsg = false
				}
				continue
			}
		}

		if !gotOpaQryLogMsg {
			t.Errorf("%d: %q: Did not get OpaQuery logrus.Entry.Level/Message/opaResp: %s/`%s`/`%s`",
				nth, tm.name, tm.qryLogLvl, tm.qryLogMsg, tm.qryOpaResp)
		}

		if !gotOpaEvalLogMsg {
			t.Errorf("%d: %q: Did not get Evaluate logrus.Entry.Level/Message/opaResp: %s/`%s`/`%s`",
				nth, tm.name, tm.evalLogLvl, tm.evalLogMsg, tm.evalOpaResp)
		}
	}
}

type MockOpaClienter struct {
	Loggr        *logrus.Logger
	RegoRespJSON string
}

func (m MockOpaClienter) String() string {
	return fmt.Sprintf(`MockOpaClienter{RegoRespJSON:"%s"}`, m.RegoRespJSON)
}

func (m MockOpaClienter) Address() string {
	return "http://localhost:8181"
}

func (m MockOpaClienter) Health() error {
	return nil
}

func (m MockOpaClienter) Query(ctx context.Context, reqData, resp interface{}) error {
	return m.CustomQuery(ctx, "", reqData, resp)
}

func (m MockOpaClienter) CustomQueryStream(ctx context.Context, document string, postReqBody []byte, respRdrFn opa_client.StreamReaderFn) error {
	return nil
}

func (m MockOpaClienter) CustomQueryBytes(ctx context.Context, document string, reqData interface{}) ([]byte, error) {
	return []byte(m.RegoRespJSON), nil
}

func (m MockOpaClienter) CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error {
	err := json.Unmarshal([]byte(m.RegoRespJSON), resp)
	m.Loggr.Debugf("CustomQuery: resp=%#v", resp)
	return err
}

type MockDecisionInputr struct {
	az.DecisionInput
}

func (d MockDecisionInputr) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*az.DecisionInput, error) {
	return &d.DecisionInput, nil
}
