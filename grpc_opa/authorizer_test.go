package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"strings"
	"reflect"
	"sort"
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
	for idx, tst := range obligationTests {
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
	        actualVal, _ := newCtx.Value(ObKey).(ObligationsType)

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		if actualVal != nil {
			t.Logf("tst#%d: before sortBy1stElem: %#v", idx, actualVal)
			actualVal.sortBy1stElem()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			// nil interface{} (untyped) does not compare equal with a nil typed value
			// https://www.calhoun.io/when-nil-isnt-equal-to-nil/
			// https://stackoverflow.com/questions/13476349/check-for-nil-and-nil-interface-in-go
			if actualVal != nil || tst.expectedVal != nil {
				t.Errorf("tst#%d: expectedVal=%#v actualVal=%#v",
					idx, tst.expectedVal, actualVal)
			}
		}
	}
}

func TestOPAResponseObligations(t *testing.T) {
	for idx, tst := range obligationTests {
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
			t.Logf("tst#%d: before sortBy1stElem: %#v", idx, actualVal)
			actualVal.sortBy1stElem()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			t.Errorf("tst#%d: expectedVal=%#v actualVal=%#v",
				idx, tst.expectedVal, actualVal)
		}
	}
}

// sortBy1stElem sorts its list of slices by their first element,
// used for deterministic testing output
func (ob *ObligationsType) sortBy1stElem() {
	sort.SliceStable(*ob, func(lhs, rhs int) bool {
		return (*ob)[lhs][0] < (*ob)[rhs][0]
	})
}

var obligationTests = []struct {
	expectedErr  error
	regoRespJSON string
	expectedVal  ObligationsType
}{
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": "bad obligations value"
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ "bad obligations value" ]
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ 3.14 ] ]
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "policy1_guid": "bad obligations value" }
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "bad_obligations_value": [ 3.14 ]}
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "policy1_guid": { "stmt0": "bad obligations value" }}
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ "a", "b" ], [ "c" ] ]
		}`,
		expectedVal:  ObligationsType{
			{ "a", "b" },
			{ "c" },
		},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {
					"stmt0": [ "a" ]
				},
				"policy2_guid": {
					"stmt0": [ "b", "c" ],
					"stmt1": [ "d" ]
				}
			}
		}`,
		expectedVal:  [][]string{
			{ "a" },
			{ "b", "c" },
			{ "d" },
		},
	},
}
