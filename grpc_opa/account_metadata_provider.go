package grpc_opa_middleware

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

const (
	// DefaultAcctEntitlementsFilteredApiPath is the OPA path for
	// acct_entitlements_filtered_api, which returns each requested account's
	// entitlements as service -> features, read straight from the bundle.
	// Sandbox entitlements are written into the bundle when it is built, so the
	// rule does not redirect a sandbox to its parent at query time and returns
	// no account details.
	DefaultAcctEntitlementsFilteredApiPath = "v1/data/authz/rbac/acct_entitlements_filtered_api"

	// DefaultAccountMetadataBySfdcApiPath is the OPA path for the combined
	// SFDC-account-ID → full account metadata lookup (single call).
	DefaultAccountMetadataBySfdcApiPath = "v1/data/authz/rbac/get_account_metadata_by_sfdc_api"
)

// AccountDetails holds account metadata as stored in the OPA bundle.
// All ID fields (CspID, ParentCspID) are strings to match the OPA data format —
// the account-metadata-publisher stores them as decimal strings, not JSON numbers.
type AccountDetails struct {
	IdentityID      string `json:"identity_id"`
	CspID           string `json:"csp_id"`
	SfdcAccountID   string `json:"sfdc_account_id"`
	AccountType     string `json:"account_type"`
	ParentAccountID string `json:"parent_account_id"`
	// ParentCspID is the pre-resolved CSP ID of the parent account.
	// Populated by the account-metadata-publisher; eliminates a second Identity
	// API call for sandbox parent lookups.
	ParentCspID string `json:"parent_csp_id"`
	State       string `json:"state"`
}

// AcctEntitlementEnrichedEntry combines an account's entitlements (from
// acct_entitlements_filtered_api) with its account details (from
// get_account_metadata_api).
//
// ResolvedAccountID is the account ID the entitlements were read for. It is
// always the account's own CSP ID: sandbox entitlements are part of the
// bundle, so no redirect to the parent is needed.
type AcctEntitlementEnrichedEntry struct {
	Entitlements      map[string][]string `json:"entitlements"`
	AccountDetails    *AccountDetails     `json:"account_details"`
	ResolvedAccountID string              `json:"resolved_account_id"`
}

// AccountMetadataProvider is the interface for looking up account metadata
// from the OPA sidecar bundle. All methods return nil result (not error) when
// the account/SFDC ID is absent from the bundle — the caller is responsible
// for treating nil as a cache miss and falling back to the Identity API.
//
// DefaultAuthorizer implements this interface. Services that only need metadata
// lookups (not full authz interception) can construct a DefaultAuthorizer via
// NewDefaultAuthorizer("") and use it solely as AccountMetadataProvider.
type AccountMetadataProvider interface {
	// GetAccountDetails returns account details for the given CSP account ID
	// by querying get_account_metadata_api.
	GetAccountDetails(ctx context.Context, cspAccountID string) (*AccountDetails, error)

	// GetEnrichedAccountMetadata returns the entitlements and account details
	// of the given CSP account ID. ResolvedAccountID is always cspAccountID.
	GetEnrichedAccountMetadata(ctx context.Context, cspAccountID string) (*AcctEntitlementEnrichedEntry, error)

	// GetAccountDetailsBySfdc returns full account details for the given SFDC ID
	// in a single OPA call, combining the SFDC→CSP and CSP→metadata lookups.
	GetAccountDetailsBySfdc(ctx context.Context, sfdcID string) (*AccountDetails, error)

	// GetCspBySfdcID resolves a SFDC account ID to a CSP account ID (string).
	// Returns ("", nil) when the SFDC ID is not present in the OPA bundle.
	GetCspBySfdcID(ctx context.Context, sfdcID string) (string, error)
}

// --- internal request/response types ---

// acctEntitlementsFilteredInput is the input for acct_entitlements_filtered_api.
type acctEntitlementsFilteredInput struct {
	AccountIDs   []string `json:"acct_entitlements_acct_ids"`
	ServiceNames []string `json:"acct_entitlements_services"`
}

// acctEntitlementsFilteredResult is the OPA response wrapper.
// Result maps csp_account_id → service → features.
type acctEntitlementsFilteredResult struct {
	Result map[string]map[string][]string `json:"result"`
}

// sfdcIDInput is the input for get_csp_by_sfdc_api and get_account_metadata_by_sfdc_api.
type sfdcIDInput struct {
	SfdcAccountID string `json:"sfdc_account_id"`
}

// cspBySfdcStringResult wraps the OPA response for get_csp_by_sfdc_api.
// The result is a string CSP ID (not int64) matching the OPA bundle format.
type cspBySfdcStringResult struct {
	Result *string `json:"result"`
}

// accountDetailsBySfdcResult wraps the OPA response for get_account_metadata_by_sfdc_api.
type accountDetailsBySfdcResult struct {
	Result *AccountDetails `json:"result"`
}

// GetEnrichedAccountMetadata queries acct_entitlements_filtered_api for the given
// CSP account ID's entitlements and get_account_metadata_api for its account
// details. Returns nil (not error) if the account has neither in the OPA bundle.
func (a *DefaultAuthorizer) GetEnrichedAccountMetadata(ctx context.Context, cspAccountID string) (*AcctEntitlementEnrichedEntry, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &acctEntitlementsFilteredInput{
			AccountIDs:   []string{cspAccountID},
			ServiceNames: []string{}, // empty = all services
		},
	}

	var apiResult acctEntitlementsFilteredResult
	if err := a.clienter.CustomQuery(ctx, a.acctEntitlementsFilteredApi, opaReq, &apiResult); err != nil {
		lgNtry.WithError(err).Error("get_enriched_account_metadata_fail")
		return nil, fmt.Errorf("get_enriched_account_metadata: %w", err)
	}

	details, err := a.GetAccountDetails(ctx, cspAccountID)
	if err != nil {
		return nil, fmt.Errorf("get_enriched_account_metadata: %w", err)
	}

	// The rule returns an empty object for a requested account that has no
	// entitlements in the bundle, so without details it counts as absent.
	entitlements := apiResult.Result[cspAccountID]
	if len(entitlements) == 0 && details == nil {
		lgNtry.WithField("csp_account_id", cspAccountID).Debug("enriched_account_metadata_not_found")
		return nil, nil
	}

	lgNtry.WithField("csp_account_id", cspAccountID).Trace("get_enriched_account_metadata_okay")

	return &AcctEntitlementEnrichedEntry{
		Entitlements:      entitlements,
		AccountDetails:    details,
		ResolvedAccountID: cspAccountID,
	}, nil
}

// GetAccountDetails returns account details for the given CSP account ID
// using get_account_metadata_api. Returns nil (not error) if absent.
func (a *DefaultAuthorizer) GetAccountDetails(ctx context.Context, cspAccountID string) (*AccountDetails, error) {
	metadata, err := a.GetAccountMetadata(ctx, cspAccountID)
	if err != nil {
		return nil, fmt.Errorf("get_account_details: %w", err)
	}
	if metadata == nil || metadata.CspID == "" {
		return nil, nil
	}
	return &AccountDetails{
		IdentityID:      metadata.IdentityID,
		CspID:           metadata.CspID,
		SfdcAccountID:   metadata.SfdcAccountID,
		AccountType:     metadata.AccountType,
		ParentAccountID: metadata.ParentAccountID,
		ParentCspID:     metadata.ParentCspID,
		State:           metadata.State,
	}, nil
}

// GetAccountDetailsBySfdc queries get_account_metadata_by_sfdc_api to resolve a
// SFDC account ID directly to full account details in a single OPA call.
// Returns nil (not error) if the SFDC ID is not in the OPA bundle.
func (a *DefaultAuthorizer) GetAccountDetailsBySfdc(ctx context.Context, sfdcID string) (*AccountDetails, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &sfdcIDInput{SfdcAccountID: sfdcID},
	}

	var apiResult accountDetailsBySfdcResult
	if err := a.clienter.CustomQuery(ctx, a.accountMetadataBySfdcApi, opaReq, &apiResult); err != nil {
		lgNtry.WithError(err).Error("get_account_details_by_sfdc_fail")
		return nil, fmt.Errorf("get_account_details_by_sfdc: %w", err)
	}

	lgNtry.WithFields(logrus.Fields{
		"sfdc_id": sfdcID,
		"result":  fmt.Sprintf("%+v", apiResult.Result),
	}).Trace("get_account_details_by_sfdc_okay")

	return apiResult.Result, nil
}

// GetCspBySfdcID resolves a SFDC account ID to a CSP account ID (string).
// Returns ("", nil) if the SFDC ID is not in the OPA bundle.
func (a *DefaultAuthorizer) GetCspBySfdcID(ctx context.Context, sfdcID string) (string, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &sfdcIDInput{SfdcAccountID: sfdcID},
	}

	var apiResult cspBySfdcStringResult
	if err := a.clienter.CustomQuery(ctx, a.cspBySfdcApi, opaReq, &apiResult); err != nil {
		lgNtry.WithError(err).Error("get_csp_by_sfdc_id_fail")
		return "", fmt.Errorf("get_csp_by_sfdc_id: %w", err)
	}

	if apiResult.Result == nil {
		lgNtry.WithField("sfdc_id", sfdcID).Debug("csp_by_sfdc_id_not_found")
		return "", nil
	}

	lgNtry.WithFields(logrus.Fields{
		"sfdc_id": sfdcID,
		"csp_id":  *apiResult.Result,
	}).Trace("get_csp_by_sfdc_id_okay")

	return *apiResult.Result, nil
}


