package grpc_opa_middleware

import (
	"context"
	"encoding/json"
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

// pathMockOpaClienter answers CustomQuery with the response registered for the
// queried OPA path and records the request sent to each path.
type pathMockOpaClienter struct {
	MockOpaClienter
	respByPath map[string]string
	requests   map[string]string
}

func (m *pathMockOpaClienter) CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error {
	reqJSON, err := json.Marshal(reqData)
	if err != nil {
		return err
	}
	if m.requests == nil {
		m.requests = map[string]string{}
	}
	m.requests[document] = string(reqJSON)
	return json.Unmarshal([]byte(m.respByPath[document]), resp)
}

// get_account_metadata_api responses and the account details they decode to.
const (
	providerTestSandboxMetadataJSON = `{
		"result": {
			"identity_id": "f0e1d2c3-b4a5-6789-0fed-cba987654321",
			"csp_id": "200",
			"sfdc_account_id": "",
			"account_type": "sandbox",
			"parent_account_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"parent_csp_id": "100",
			"state": "active"
		}
	}`
	providerTestRegularMetadataJSON = `{
		"result": {
			"identity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"csp_id": "100",
			"sfdc_account_id": "001ABC000XYZ123",
			"account_type": "regular",
			"parent_account_id": "",
			"parent_csp_id": "",
			"state": "active"
		}
	}`
)

var (
	providerTestSandboxDetails = &AccountDetails{
		IdentityID:      "f0e1d2c3-b4a5-6789-0fed-cba987654321",
		CspID:           "200",
		SfdcAccountID:   "",
		AccountType:     "sandbox",
		ParentAccountID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		ParentCspID:     "100",
		State:           "active",
	}
	providerTestRegularDetails = &AccountDetails{
		IdentityID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		CspID:           "100",
		SfdcAccountID:   "001ABC000XYZ123",
		AccountType:     "regular",
		ParentAccountID: "",
		ParentCspID:     "",
		State:           "active",
	}
)

func TestGetEnrichedAccountMetadataMockOpaClient(t *testing.T) {
	testMap := []struct {
		name         string
		accountID    string
		filteredJSON string // acct_entitlements_filtered_api response
		metadataJSON string // get_account_metadata_api response
		expectErr    bool
		expectedVal  *AcctEntitlementEnrichedEntry
	}{
		{
			name:         "sandbox account with entitlements and details",
			accountID:    "200",
			filteredJSON: `{"result": {"200": {"license": ["feature_a", "feature_b"]}}}`,
			metadataJSON: providerTestSandboxMetadataJSON,
			expectErr:    false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"feature_a", "feature_b"},
				},
				AccountDetails:    providerTestSandboxDetails,
				ResolvedAccountID: "200",
			},
		},
		{
			name:         "regular account resolves to itself",
			accountID:    "100",
			filteredJSON: `{"result": {"100": {"license": ["feature_x"]}}}`,
			metadataJSON: providerTestRegularMetadataJSON,
			expectErr:    false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"feature_x"},
				},
				AccountDetails:    providerTestRegularDetails,
				ResolvedAccountID: "100",
			},
		},
		{
			name:         "entitlements without account metadata",
			accountID:    "264",
			filteredJSON: `{"result": {"264": {"license": ["some_feature"]}}}`,
			metadataJSON: `{"result": null}`,
			expectErr:    false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements: map[string][]string{
					"license": {"some_feature"},
				},
				ResolvedAccountID: "264",
			},
		},
		{
			name:         "account metadata without entitlements",
			accountID:    "100",
			filteredJSON: `{"result": {"100": {}}}`,
			metadataJSON: providerTestRegularMetadataJSON,
			expectErr:    false,
			expectedVal: &AcctEntitlementEnrichedEntry{
				Entitlements:      map[string][]string{},
				AccountDetails:    providerTestRegularDetails,
				ResolvedAccountID: "100",
			},
		},
		{
			name:         "account with neither returns nil",
			accountID:    "999",
			filteredJSON: `{"result": {"999": {}}}`,
			metadataJSON: `{"result": null}`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         "null result returns nil",
			accountID:    "999",
			filteredJSON: `{"result": null}`,
			metadataJSON: `{"result": null}`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         "invalid entitlements json returns error",
			accountID:    "200",
			filteredJSON: `[null]`,
			metadataJSON: providerTestSandboxMetadataJSON,
			expectErr:    true,
			expectedVal:  nil,
		},
		{
			name:         "invalid metadata json returns error",
			accountID:    "200",
			filteredJSON: `{"result": {"200": {"license": ["feat"]}}}`,
			metadataJSON: `[null]`,
			expectErr:    true,
			expectedVal:  nil,
		},
	}

	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := &pathMockOpaClienter{
				MockOpaClienter: MockOpaClienter{Loggr: logrus.StandardLogger()},
				respByPath: map[string]string{
					DefaultAcctEntitlementsFilteredApiPath: tm.filteredJSON,
					DefaultAccountMetadataApiPath:          tm.metadataJSON,
				},
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(mockOpaClienter),
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
		name         string
		accountID    string
		metadataJSON string // get_account_metadata_api response
		expectErr    bool
		expectedVal  *AccountDetails
	}{
		{
			name:         "sandbox account returns details",
			accountID:    "200",
			metadataJSON: providerTestSandboxMetadataJSON,
			expectErr:    false,
			expectedVal:  providerTestSandboxDetails,
		},
		{
			name:         "regular account returns details",
			accountID:    "100",
			metadataJSON: providerTestRegularMetadataJSON,
			expectErr:    false,
			expectedVal:  providerTestRegularDetails,
		},
		{
			name:         "metadata without csp_id returns nil",
			accountID:    "264",
			metadataJSON: `{"result": {}}`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         "account not found returns nil",
			accountID:    "999",
			metadataJSON: `{"result": null}`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         "no result key returns nil",
			accountID:    "999",
			metadataJSON: `{}`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         "invalid json returns error",
			accountID:    "200",
			metadataJSON: `[null]`,
			expectErr:    true,
			expectedVal:  nil,
		},
	}

	ctx := newTestContext(t)

	for nth, tm := range testMap {
		t.Run(tm.name, func(t *testing.T) {
			mockOpaClienter := &pathMockOpaClienter{
				MockOpaClienter: MockOpaClienter{Loggr: logrus.StandardLogger()},
				respByPath: map[string]string{
					DefaultAccountMetadataApiPath: tm.metadataJSON,
					// acct_entitlements_filtered_api returns entitlements only, so
					// details must not come from it.
					DefaultAcctEntitlementsFilteredApiPath: `{"result": {"` + tm.accountID + `": {"license": ["feat"]}}}`,
				},
			}
			auther := NewDefaultAuthorizer("bogus_unused_application_value",
				WithOpaClienter(mockOpaClienter),
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

			wantReq := `{"input":{"csp_account_id":"` + tm.accountID + `"}}`
			if gotReq := mockOpaClienter.requests[DefaultAccountMetadataApiPath]; gotReq != wantReq {
				t.Errorf("get_account_metadata_api request=%s, want %s", gotReq, wantReq)
			}
			if _, queried := mockOpaClienter.requests[DefaultAcctEntitlementsFilteredApiPath]; queried {
				t.Errorf("GetAccountDetails must not query acct_entitlements_filtered_api")
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
