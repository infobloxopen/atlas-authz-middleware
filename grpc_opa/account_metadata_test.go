package grpc_opa_middleware

import (
	"context"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

func TestGetAccountMetadataMockOpaClient(t *testing.T) {
	testMap := []struct {
		name        string
		accountID   string
		regoJSON    string
		expectErr   bool
		expectedVal *AccountMetadataResult
	}{
		{
			name:      "sandbox account with parent",
			accountID: "200",
			regoJSON: `{
				"result": {
					"identity_id": "f0e1d2c3-b4a5-6789-0fed-cba987654321",
					"csp_id": 200,
					"sfdc_account_id": "",
					"account_type": "sandbox",
					"parent_account_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					"parent_csp_id": 100,
					"state": "active"
				}
			}`,
			expectErr: false,
			expectedVal: &AccountMetadataResult{
				IdentityID:      "f0e1d2c3-b4a5-6789-0fed-cba987654321",
				CspID:           200,
				SfdcAccountID:   "",
				AccountType:     "sandbox",
				ParentAccountID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				ParentCspID:     100,
				State:           "active",
			},
		},
		{
			name:      "regular account",
			accountID: "100",
			regoJSON: `{
				"result": {
					"identity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					"csp_id": 100,
					"sfdc_account_id": "001ABC000XYZ123",
					"account_type": "regular",
					"parent_account_id": "",
					"parent_csp_id": 0,
					"state": "active"
				}
			}`,
			expectErr: false,
			expectedVal: &AccountMetadataResult{
				IdentityID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				CspID:           100,
				SfdcAccountID:   "001ABC000XYZ123",
				AccountType:     "regular",
				ParentAccountID: "",
				ParentCspID:     0,
				State:           "active",
			},
		},
		{
			name:        "account not found returns nil result",
			accountID:   "999",
			regoJSON:    `{"result": null}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "no result key returns nil result",
			accountID:   "200",
			regoJSON:    `{"rresult": null}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "invalid json returns error",
			accountID:   "200",
			regoJSON:    `[null]`,
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
			RegoRespJSON: tm.regoJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetAccountMetadata(ctx, tm.accountID)
		t.Logf("%d: %q: actualErr=%v, actualVal=%+v", nth, tm.name, actualErr, actualVal)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualVal != nil {
			t.Errorf("%d: %q: FAIL: returned val should be nil if err returned", nth, tm.name)
		}

		if !reflect.DeepEqual(actualVal, tm.expectedVal) {
			t.Errorf("%d: %q: FAIL: expectedVal=%+v actualVal=%+v",
				nth, tm.name, tm.expectedVal, actualVal)
		}
	}
}

func TestGetParentCspIdMockOpaClient(t *testing.T) {
	testMap := []struct {
		name      string
		accountID string
		regoJSON  string
		expectErr bool
		expectVal int64
	}{
		{
			name:      "sandbox returns parent id",
			accountID: "200",
			regoJSON:  `{"result": 100}`,
			expectErr: false,
			expectVal: 100,
		},
		{
			name:      "non-sandbox returns zero",
			accountID: "100",
			regoJSON:  `{"result": null}`,
			expectErr: false,
			expectVal: 0,
		},
		{
			name:      "account not found returns zero",
			accountID: "999",
			regoJSON:  `{}`,
			expectErr: false,
			expectVal: 0,
		},
		{
			name:      "invalid json returns error",
			accountID: "200",
			regoJSON:  `[null]`,
			expectErr: true,
			expectVal: 0,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetParentCspId(ctx, tm.accountID)
		t.Logf("%d: %q: actualErr=%v, actualVal=%d", nth, tm.name, actualErr, actualVal)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualVal != tm.expectVal {
			t.Errorf("%d: %q: FAIL: expectVal=%d actualVal=%d",
				nth, tm.name, tm.expectVal, actualVal)
		}
	}
}

func TestGetCspBySfdcMockOpaClient(t *testing.T) {
	testMap := []struct {
		name      string
		sfdcID    string
		regoJSON  string
		expectErr bool
		expectVal int64
	}{
		{
			name:      "valid sfdc returns csp id",
			sfdcID:    "001ABC000XYZ123",
			regoJSON:  `{"result": 100}`,
			expectErr: false,
			expectVal: 100,
		},
		{
			name:      "unknown sfdc returns zero",
			sfdcID:    "001UNKNOWN",
			regoJSON:  `{"result": null}`,
			expectErr: false,
			expectVal: 0,
		},
		{
			name:      "invalid json returns error",
			sfdcID:    "001ABC",
			regoJSON:  `[null]`,
			expectErr: true,
			expectVal: 0,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetCspBySfdc(ctx, tm.sfdcID)
		t.Logf("%d: %q: actualErr=%v, actualVal=%d", nth, tm.name, actualErr, actualVal)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualVal != tm.expectVal {
			t.Errorf("%d: %q: FAIL: expectVal=%d actualVal=%d",
				nth, tm.name, tm.expectVal, actualVal)
		}
	}
}

func TestGetSandboxesForParentMockOpaClient(t *testing.T) {
	testMap := []struct {
		name      string
		parentID  string
		regoJSON  string
		expectErr bool
		expectVal []int64
	}{
		{
			name:      "parent with sandboxes",
			parentID:  "100",
			regoJSON:  `{"result": [200, 201]}`,
			expectErr: false,
			expectVal: []int64{200, 201},
		},
		{
			name:      "parent with no sandboxes returns nil",
			parentID:  "999",
			regoJSON:  `{"result": null}`,
			expectErr: false,
			expectVal: nil,
		},
		{
			name:      "empty result returns nil",
			parentID:  "100",
			regoJSON:  `{}`,
			expectErr: false,
			expectVal: nil,
		},
		{
			name:      "invalid json returns error",
			parentID:  "100",
			regoJSON:  `[null]`,
			expectErr: true,
			expectVal: nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetSandboxesForParent(ctx, tm.parentID)
		t.Logf("%d: %q: actualErr=%v, actualVal=%v", nth, tm.name, actualErr, actualVal)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if !reflect.DeepEqual(actualVal, tm.expectVal) {
			t.Errorf("%d: %q: FAIL: expectVal=%v actualVal=%v",
				nth, tm.name, tm.expectVal, actualVal)
		}
	}
}
