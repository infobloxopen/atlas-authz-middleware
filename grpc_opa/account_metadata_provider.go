package grpc_opa_middleware

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

const (
	// DefaultAcctEntitlementsFilteredApiPath is the OPA path for the enriched
	// acct_entitlements_filtered_api that returns entitlements + account_details +
	// resolved_account_id per account in a single call.
	// Sandbox-parent resolution is built into this rule: when
	// authz_settings.sandbox_parent_entitlement_enabled is true, ResolvedAccountID
	// is the PARENT's CSP ID for STATE-1 sandbox accounts. Consumers must use
	// ResolvedAccountID for license/entitlement lookups so that after mirroring is
	// disabled, reads automatically redirect to the parent without any code change.
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

// AcctEntitlementEnrichedEntry is the per-account entry returned by
// acct_entitlements_filtered_api. It combines entitlements, account details,
// and the resolved account ID in a single OPA call.
//
// ResolvedAccountID is the account ID that entitlements were read from:
//   - For STATE-1 sandbox accounts (sandbox_parent_entitlement_enabled=true):
//     this is the PARENT's CSP ID.
//   - For all other accounts: this equals the account's own CSP ID.
//
// Consumers MUST use ResolvedAccountID for license/entitlement lookups.
// This ensures that after mirroring is disabled, existing consumers
// automatically redirect reads to the parent without any code change.
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
	// by querying acct_entitlements_filtered_api. Sandbox-parent resolution is
	// applied transparently via ResolvedAccountID.
	GetAccountDetails(ctx context.Context, cspAccountID string) (*AccountDetails, error)

	// GetEnrichedAccountMetadata returns the full enriched entry
	// (entitlements + account_details + resolved_account_id) for the given CSP
	// account ID. Use ResolvedAccountID from the result for all downstream lookups.
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
// Result is a map of csp_account_id → AcctEntitlementEnrichedEntry.
type acctEntitlementsFilteredResult struct {
	Result map[string]*AcctEntitlementEnrichedEntry `json:"result"`
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
// CSP account ID and returns the full enriched entry including ResolvedAccountID.
// Returns nil (not error) if the account is not in the OPA bundle.
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

	entry, found := apiResult.Result[cspAccountID]
	if !found || entry == nil {
		lgNtry.WithField("csp_account_id", cspAccountID).Debug("enriched_account_metadata_not_found")
		return nil, nil
	}

	lgNtry.WithFields(logrus.Fields{
		"csp_account_id":      cspAccountID,
		"resolved_account_id": entry.ResolvedAccountID,
	}).Trace("get_enriched_account_metadata_okay")

	return entry, nil
}

// GetAccountDetails returns account details for the given CSP account ID
// using acct_entitlements_filtered_api. Returns nil (not error) if absent.
func (a *DefaultAuthorizer) GetAccountDetails(ctx context.Context, cspAccountID string) (*AccountDetails, error) {
	entry, err := a.GetEnrichedAccountMetadata(ctx, cspAccountID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	if entry.AccountDetails == nil || entry.AccountDetails.CspID == "" {
		return nil, nil
	}
	return entry.AccountDetails, nil
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


