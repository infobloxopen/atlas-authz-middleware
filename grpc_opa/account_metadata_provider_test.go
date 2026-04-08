package grpc_opa_middleware

import (
	"context"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

// newTestContext creates a context with the testing.T propagated for mock-internal
// logging, matching the pattern in account_metadata_test.go.
func newTestContext(t *testing.T) context.Context {
	t.Helper()
	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	return ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))
}

func TestGetEnrichedAccountMetadataMockOpaClient(t *testing.T) {
	testMap := []struct {
		name        string
		accountID   string
		regoJSON    string
		expectErr   bool
		expectedVal *AcctEntitlementEnrichedEntry
	}{
		{
			name:      "sandbox account with parent and entitlements",
			accountID: "200",
			regoJSON: `{
				"result": {
					"200": {
						"entitlements": {
							"license": ["feature_a", "feature_b"]
						},
						"account_details": {
							"identity_id": "f0e1d2c3-b4a5-6789-0fed-cba987654321",
							"csp_id": "200",
							"sfdc_account_id": "",
							"account_type": "sandbox",
							"parent_account_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
							"parent_csp_id": "100",
							"state": "active"
						},
						"resolved_account_id": "100"
					}
				}
			}`,
			expectErr: false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"feature_a", "feature_b"},
				},
				AccountDetails: &AccountDetails{
					IdentityID:      "f0e1d2c3-b4a5-6789-0fed-cba987654321",
					CspID:           "200",
					SfdcAccountID:   "",
					AccountType:     "sandbox",
					ParentAccountID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					ParentCspID:     "100",
					State:           "active",
				},
				ResolvedAccountID: "100",
			},
		},
		{
			name:      "regular account resolves to itself",
			accountID: "100",
			regoJSON: `{
				"result": {
					"100": {
						"entitlements": {
							"license": ["feature_x"]
						},
						"account_details": {
							"identity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
							"csp_id": "100",
							"sfdc_account_id": "001ABC000XYZ123",
							"account_type": "regular",
							"parent_account_id": "",
							"parent_csp_id": "",
							"state": "active"
						},
						"resolved_account_id": "100"
					}
				}
			}`,
			expectErr: false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"feature_x"},
				},
				AccountDetails: &AccountDetails{
					IdentityID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					CspID:           "100",
					SfdcAccountID:   "001ABC000XYZ123",
					AccountType:     "regular",
					ParentAccountID: "",
					ParentCspID:     "",
					State:           "active",
				},
				ResolvedAccountID: "100",
			},
		},
		{
			name:      "account with entitlements but missing from account_metadata (empty account_details)",
			accountID: "264",
			regoJSON: `{
				"result": {
					"264": {
						"entitlements": {
							"license": ["some_feature"]
						},
						"account_details": {},
						"resolved_account_id": "264"
					}
				}
			}`,
			expectErr: false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"some_feature"},
				},
				AccountDetails:    &AccountDetails{},
				ResolvedAccountID: "264",
			},
		},
		{
			name:        "account not found returns nil",
			accountID:   "999",
			regoJSON:    `{"result": {}}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "null result returns nil",
			accountID:   "999",
			regoJSON:    `{"result": null}`,
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
	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tm.regoJSON,
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			actualVal, actualErr := auther.GetEnrichedAccountMetadata(ctx, tm.accountID)
			t.Logf("%d: %q: actualErr=%v, actualVal=%+v", nth, tm.name, actualErr, actualVal)

			if tm.expectErr && actualErr == nil {
				t.Errorf("expected err, but got no err")
			} else if !tm.expectErr && actualErr != nil {
				t.Errorf("got unexpected err=%s", actualErr)
			}

			if actualErr != nil && actualVal != nil {
				t.Errorf("returned val should be nil if err returned")
			}

			if !reflect.DeepEqual(actualVal, tm.expectedVal) {
				t.Errorf("expectedVal=%+v actualVal=%+v", tm.expectedVal, actualVal)
			}
		})
	}
}

func TestGetAccountDetailsMockOpaClient(t *testing.T) {
	testMap := []struct {
		name        string
		accountID   string
		regoJSON    string
		expectErr   bool
		expectedVal *AccountDetails
	}{
		{
			name:      "sandbox account returns details",
			accountID: "200",
			regoJSON: `{
				"result": {
					"200": {
						"entitlements": {"license": ["feat"]},
						"account_details": {
							"identity_id": "f0e1d2c3-b4a5-6789-0fed-cba987654321",
							"csp_id": "200",
							"sfdc_account_id": "",
							"account_type": "sandbox",
							"parent_account_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
							"parent_csp_id": "100",
							"state": "active"
						},
						"resolved_account_id": "100"
					}
				}
			}`,
			expectErr: false,
			expectedVal: &AccountDetails{
				IdentityID:      "f0e1d2c3-b4a5-6789-0fed-cba987654321",
				CspID:           "200",
				SfdcAccountID:   "",
				AccountType:     "sandbox",
				ParentAccountID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				ParentCspID:     "100",
				State:           "active",
			},
		},
		{
			name:      "regular account returns details",
			accountID: "100",
			regoJSON: `{
				"result": {
					"100": {
						"entitlements": {"license": ["feat"]},
						"account_details": {
							"identity_id": "a1b2c3d4",
							"csp_id": "100",
							"sfdc_account_id": "001ABC",
							"account_type": "regular",
							"parent_account_id": "",
							"parent_csp_id": "",
							"state": "active"
						},
						"resolved_account_id": "100"
					}
				}
			}`,
			expectErr: false,
			expectedVal: &AccountDetails{
				IdentityID:      "a1b2c3d4",
				CspID:           "100",
				SfdcAccountID:   "001ABC",
				AccountType:     "regular",
				ParentAccountID: "",
				ParentCspID:     "",
				State:           "active",
			},
		},
		{
			name:      "empty account_details (missing from account_metadata) returns nil - CspID empty",
			accountID: "264",
			regoJSON: `{
				"result": {
					"264": {
						"entitlements": {"license": ["some_feature"]},
						"account_details": {},
						"resolved_account_id": "264"
					}
				}
			}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:      "null account_details returns nil",
			accountID: "300",
			regoJSON: `{
				"result": {
					"300": {
						"entitlements": {"license": ["feat"]},
						"account_details": null,
						"resolved_account_id": "300"
					}
				}
			}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "account not found in result returns nil",
			accountID:   "999",
			regoJSON:    `{"result": {}}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "null result returns nil",
			accountID:   "999",
			regoJSON:    `{"result": null}`,
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
	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tm.regoJSON,
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			actualVal, actualErr := auther.GetAccountDetails(ctx, tm.accountID)
			t.Logf("%d: %q: actualErr=%v, actualVal=%+v", nth, tm.name, actualErr, actualVal)

			if tm.expectErr && actualErr == nil {
				t.Errorf("expected err, but got no err")
			} else if !tm.expectErr && actualErr != nil {
				t.Errorf("got unexpected err=%s", actualErr)
			}

			if actualErr != nil && actualVal != nil {
				t.Errorf("returned val should be nil if err returned")
			}

			if !reflect.DeepEqual(actualVal, tm.expectedVal) {
				t.Errorf("expectedVal=%+v actualVal=%+v", tm.expectedVal, actualVal)
			}
		})
	}
}

func TestGetAccountDetailsBySfdcMockOpaClient(t *testing.T) {
	testMap := []struct {
		name        string
		sfdcID      string
		regoJSON    string
		expectErr   bool
		expectedVal *AccountDetails
	}{
		{
			name:   "valid sfdc returns account details",
			sfdcID: "001ABC000XYZ123",
			regoJSON: `{
				"result": {
					"identity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					"csp_id": "100",
					"sfdc_account_id": "001ABC000XYZ123",
					"account_type": "regular",
					"parent_account_id": "",
					"parent_csp_id": "",
					"state": "active"
				}
			}`,
			expectErr: false,
			expectedVal: &AccountDetails{
				IdentityID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				CspID:           "100",
				SfdcAccountID:   "001ABC000XYZ123",
				AccountType:     "regular",
				ParentAccountID: "",
				ParentCspID:     "",
				State:           "active",
			},
		},
		{
			name:        "unknown sfdc returns nil",
			sfdcID:      "001UNKNOWN",
			regoJSON:    `{"result": null}`,
			expectErr:   false,
			expectedVal: nil,
		},
		{
			name:        "invalid json returns error",
			sfdcID:      "001ABC",
			regoJSON:    `[null]`,
			expectErr:   true,
			expectedVal: nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tm.regoJSON,
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			actualVal, actualErr := auther.GetAccountDetailsBySfdc(ctx, tm.sfdcID)
			t.Logf("%d: %q: actualErr=%v, actualVal=%+v", nth, tm.name, actualErr, actualVal)

			if tm.expectErr && actualErr == nil {
				t.Errorf("expected err, but got no err")
			} else if !tm.expectErr && actualErr != nil {
				t.Errorf("got unexpected err=%s", actualErr)
			}

			if actualErr != nil && actualVal != nil {
				t.Errorf("returned val should be nil if err returned")
			}

			if !reflect.DeepEqual(actualVal, tm.expectedVal) {
				t.Errorf("expectedVal=%+v actualVal=%+v", tm.expectedVal, actualVal)
			}
		})
	}
}

func TestGetCspBySfdcIDMockOpaClient(t *testing.T) {
	testMap := []struct {
		name      string
		sfdcID    string
		regoJSON  string
		expectErr bool
		expectVal string
	}{
		{
			name:      "valid sfdc returns csp id string",
			sfdcID:    "001ABC000XYZ123",
			regoJSON:  `{"result": "100"}`,
			expectErr: false,
			expectVal: "100",
		},
		{
			name:      "unknown sfdc returns empty string",
			sfdcID:    "001UNKNOWN",
			regoJSON:  `{"result": null}`,
			expectErr: false,
			expectVal: "",
		},
		{
			name:      "no result key returns empty string",
			sfdcID:    "001ABC",
			regoJSON:  `{}`,
			expectErr: false,
			expectVal: "",
		},
		{
			name:      "invalid json returns error",
			sfdcID:    "001ABC",
			regoJSON:  `[null]`,
			expectErr: true,
			expectVal: "",
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := MockOpaClienter{
				Loggr:        stdLoggr,
				RegoRespJSON: tm.regoJSON,
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(&mockOpaClienter),
			)

			actualVal, actualErr := auther.GetCspBySfdcID(ctx, tm.sfdcID)
			t.Logf("%d: %q: actualErr=%v, actualVal=%q", nth, tm.name, actualErr, actualVal)

			if tm.expectErr && actualErr == nil {
				t.Errorf("expected err, but got no err")
			} else if !tm.expectErr && actualErr != nil {
				t.Errorf("got unexpected err=%s", actualErr)
			}

			if actualVal != tm.expectVal {
				t.Errorf("expectVal=%q actualVal=%q", tm.expectVal, actualVal)
			}
		})
	}
}
