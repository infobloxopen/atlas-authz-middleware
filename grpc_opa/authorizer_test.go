package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
	logrustesthook "github.com/sirupsen/logrus/hooks/test"
)

func TestRedactJWT(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	if redacted := redactJWT(token); !strings.HasSuffix(redacted, REDACTED) {

		t.Errorf("got: %s, wanted: %s", redacted, REDACTED)
	}
}

func Test_parseEndpoint(t *testing.T) {
	expected := "TagService.ListRetiredTags"
	if endpoint := parseEndpoint("/service.TagService/ListRetiredTags"); expected != endpoint {
		t.Errorf("got: %s, wanted: %s", endpoint, expected)
	}

}

func Test_addObligations(t *testing.T) {
	for idx, tst := range obligationsNodeTests {
		ctx := context.Background()
		var opaResp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &opaResp)
		if err != nil {
			t.Errorf("tst#%d: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: opaResp=%#v", idx, opaResp)
		newCtx, actualErr := addObligations(ctx, opaResp)

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		actualVal, _ := newCtx.Value(ObKey).(*ObligationsNode)
		if actualVal != nil {
			t.Logf("tst#%d: before DeepSort: %s", idx, actualVal)
			actualVal.DeepSort()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			// nil interface{} (untyped) does not compare equal with a nil typed value
			// https://www.calhoun.io/when-nil-isnt-equal-to-nil/
			// https://stackoverflow.com/questions/13476349/check-for-nil-and-nil-interface-in-go
			if actualVal != nil || tst.expectedVal != nil {
				t.Errorf("tst#%d: expectedVal=%s actualVal=%s",
					idx, tst.expectedVal, actualVal)
			}
		}
	}
}

func TestOPAResponseObligations(t *testing.T) {
	for idx, tst := range obligationsNodeTests {
		var opaResp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &opaResp)
		if err != nil {
			t.Errorf("tst#%d: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: opaResp=%#v", idx, opaResp)
		actualVal, actualErr := opaResp.Obligations()

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		if actualVal != nil {
			t.Logf("tst#%d: before DeepSort: %s", idx, actualVal)
			actualVal.DeepSort()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			t.Errorf("tst#%d: expectedVal=%s actualVal=%s",
				idx, tst.expectedVal, actualVal)
		}
	}
}

func TestAffirmAuthorization(t *testing.T) {
	ErrBoom := errors.New("boom")

	testMap := []struct {
		name        string
		opaEvaltor  OpaEvaluator
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
			WithClaimsVerifier(utils_test.NullClaimsVerifier),
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
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(logrus.StandardLogger()))

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			RegoRespJSON: tm.regoRespJSON,
		}
		auther := NewDefaultAuthorizer("app",
			WithOpaClienter(&mockOpaClienter),
			WithClaimsVerifier(utils_test.NullClaimsVerifier),
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

type MockOpaClienter struct{
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

func (m MockOpaClienter) Query(ctx context.Context, data interface{}, resp interface{}) error {
	return m.CustomQuery(ctx, "", data, resp)
}

func (m MockOpaClienter) CustomQuery(ctx context.Context, document string, data interface{}, resp interface{}) error {
	return json.Unmarshal([]byte(m.RegoRespJSON), resp)
}

