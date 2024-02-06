package opautil

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	az "github.com/infobloxopen/atlas-authz-middleware/common/authorizer"
)

func Test_AddObligations(t *testing.T) {
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
		newCtx, actualErr := AddObligations(ctx, opaResp)

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		actualVal, _ := newCtx.Value(az.ObKey).(*ObligationsNode)
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
