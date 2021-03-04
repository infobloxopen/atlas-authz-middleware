package grpc_opa_middleware

import (
	"context"
	"encoding/json"
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
		var resp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &resp)
		if err != nil {
			t.Errorf("tst#%d: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: resp=%#v", idx, resp)
		newCtx, actualErr := addObligations(ctx, resp)

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
		var resp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &resp)
		if err != nil {
			t.Errorf("tst#%d: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: resp=%#v", idx, resp)
		actualVal, actualErr := resp.Obligations()

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
