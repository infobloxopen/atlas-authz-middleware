package grpc_opa_middleware

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

const (
	// DefaultAccountMetadataApiPath is default OPA path to fetch account metadata
	DefaultAccountMetadataApiPath = "v1/data/authz/rbac/get_account_metadata_api"

	// DefaultParentCspIdApiPath is default OPA path to resolve sandbox → parent CSP ID
	DefaultParentCspIdApiPath = "v1/data/authz/rbac/get_parent_csp_id_api"

	// DefaultCspBySfdcApiPath is default OPA path to resolve SFDC → CSP ID
	DefaultCspBySfdcApiPath = "v1/data/authz/rbac/get_csp_by_sfdc_api"

	// DefaultSandboxesForParentApiPath is default OPA path to fetch sandbox CSP IDs for a parent
	DefaultSandboxesForParentApiPath = "v1/data/authz/rbac/get_sandboxes_for_parent_api"
)

// AccountMetadataApiInput is the input payload for get_account_metadata_api
// and get_parent_csp_id_api (both use account_id as input key)
type AccountMetadataApiInput struct {
	AccountID string `json:"account_id"`
}

// SfdcApiInput is the input payload for get_csp_by_sfdc_api
type SfdcApiInput struct {
	SFDCAccountID string `json:"sfdc_account_id"`
}

// ParentApiInput is the input payload for get_sandboxes_for_parent_api
type ParentApiInput struct {
	ParentAccountID string `json:"parent_account_id"`
}

// AccountMetadataResult is the account metadata returned from OPA
type AccountMetadataResult struct {
	IdentityID      string `json:"identity_id"`
	CspID           int64  `json:"csp_id"`
	SfdcAccountID   string `json:"sfdc_account_id"`
	AccountType     string `json:"account_type"`
	ParentAccountID string `json:"parent_account_id"`
	ParentCspID     int64  `json:"parent_csp_id"`
	State           string `json:"state"`
}

// AccountMetadataApiResult wraps the OPA response for get_account_metadata_api
type AccountMetadataApiResult struct {
	Result *AccountMetadataResult `json:"result"`
}

// ParentCspIdApiResult wraps the OPA response for get_parent_csp_id_api
type ParentCspIdApiResult struct {
	Result *int64 `json:"result"`
}

// CspBySfdcApiResult wraps the OPA response for get_csp_by_sfdc_api
type CspBySfdcApiResult struct {
	Result *int64 `json:"result"`
}

// SandboxesForParentApiResult wraps the OPA response for get_sandboxes_for_parent_api
type SandboxesForParentApiResult struct {
	Result []int64 `json:"result"`
}

// GetAccountMetadata queries OPA sidecar for account metadata by CSP account ID.
// Returns nil result (not error) if the account is not found in the OPA bundle data.
func (a *DefaultAuthorizer) GetAccountMetadata(ctx context.Context, accountID string) (*AccountMetadataResult, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &AccountMetadataApiInput{
			AccountID: accountID,
		},
	}

	var apiResult AccountMetadataApiResult
	err := a.clienter.CustomQuery(ctx, a.accountMetadataApi, opaReq, &apiResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_account_metadata_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"account_id": accountID,
		"result":     fmt.Sprintf("%+v", apiResult.Result),
	}).Trace("get_account_metadata_okay")

	return apiResult.Result, nil
}

// GetParentCspId queries OPA sidecar for the parent CSP ID of a sandbox account.
// Returns 0 and nil error if the account is not a sandbox or not found.
func (a *DefaultAuthorizer) GetParentCspId(ctx context.Context, sandboxCspID string) (int64, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &AccountMetadataApiInput{
			AccountID: sandboxCspID,
		},
	}

	var apiResult ParentCspIdApiResult
	err := a.clienter.CustomQuery(ctx, a.parentCspIdApi, opaReq, &apiResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_parent_csp_id_fail")
		return 0, err
	}

	var parentID int64
	if apiResult.Result != nil {
		parentID = *apiResult.Result
	}

	lgNtry.WithFields(logrus.Fields{
		"sandbox_csp_id": sandboxCspID,
		"parent_csp_id":  parentID,
	}).Trace("get_parent_csp_id_okay")

	return parentID, nil
}

// GetCspBySfdc queries OPA sidecar for CSP account ID by SFDC account ID.
// Returns 0 and nil error if the SFDC account is not found.
func (a *DefaultAuthorizer) GetCspBySfdc(ctx context.Context, sfdcAccountID string) (int64, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &SfdcApiInput{
			SFDCAccountID: sfdcAccountID,
		},
	}

	var apiResult CspBySfdcApiResult
	err := a.clienter.CustomQuery(ctx, a.cspBySfdcApi, opaReq, &apiResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_csp_by_sfdc_fail")
		return 0, err
	}

	var cspID int64
	if apiResult.Result != nil {
		cspID = *apiResult.Result
	}

	lgNtry.WithFields(logrus.Fields{
		"sfdc_account_id": sfdcAccountID,
		"csp_id":          cspID,
	}).Trace("get_csp_by_sfdc_okay")

	return cspID, nil
}

// GetSandboxesForParent queries OPA sidecar for all sandbox CSP IDs belonging to a parent.
// Returns nil (not error) if the parent has no sandboxes or is not found.
func (a *DefaultAuthorizer) GetSandboxesForParent(ctx context.Context, parentCspID string) ([]int64, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	opaReq := OPARequest{
		Input: &ParentApiInput{
			ParentAccountID: parentCspID,
		},
	}

	var apiResult SandboxesForParentApiResult
	err := a.clienter.CustomQuery(ctx, a.sandboxesForParentApi, opaReq, &apiResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_sandboxes_for_parent_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"parent_csp_id": parentCspID,
		"sandbox_ids":   apiResult.Result,
	}).Trace("get_sandboxes_for_parent_okay")

	return apiResult.Result, nil
}
