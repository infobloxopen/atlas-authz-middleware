package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"reflect"
	"testing"
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
	claimsVerifier = nullClaimsVerifier

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

	ctx := context.WithValue(context.Background(), TestingTContextKey, t)

	for nth, tm := range testMap {
		auther := NewDefaultAuthorizer("app", WithOpaEvaluator(tm.opaEvaltor))

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
