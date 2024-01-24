package grpc_opa_middleware

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/infobloxopen/atlas-authz-middleware/common/opautil"
	logrus "github.com/sirupsen/logrus"
)

// AcctEntitlementsApiInput is the input payload for acct_entitlements_api
type AcctEntitlementsApiInput struct {
	AccountIDs   []string `json:"acct_entitlements_acct_ids"`
	ServiceNames []string `json:"acct_entitlements_services"`
}

// AcctEntitlementsType is a convenience data type, returned by GetAcctEntitlements()
// (map of acct_id to map of service to array of features)
type AcctEntitlementsType map[string]map[string][]string

// AcctEntitlementsApiResult is the data type json.Unmarshaled from OPA RESTAPI query to acct_entitlements_api
type AcctEntitlementsApiResult struct {
	Result *AcctEntitlementsType `json:"result"`
}

// GetAcctEntitlementsBytes queries account entitled features data
// for the specified account-ids and entitled-services.
// If both account-ids and entitled-services are empty,
// then data for all entitled-services in all accounts are returned.
// Returns the raw JSON string response
func (a *DefaultAuthorizer) GetAcctEntitlementsBytes(ctx context.Context, accountIDs, serviceNames []string) ([]byte, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	if accountIDs == nil {
		accountIDs = []string{}
	}
	if serviceNames == nil {
		serviceNames = []string{}
	}

	opaReq := opautil.OPARequest{
		Input: &AcctEntitlementsApiInput{
			AccountIDs:   accountIDs,
			ServiceNames: serviceNames,
		},
	}

	rawBytes, err := a.clienter.CustomQueryBytes(ctx, a.acctEntitlementsApi, opaReq)
	if err != nil {
		lgNtry.WithError(err).Error("get_acct_entitlements_raw_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"rawBytes": string(rawBytes),
	}).Trace("get_acct_entitlements_raw_okay")

	return rawBytes, nil
}

// GetAcctEntitlements queries account entitled features data
// for the specified account-ids and entitled-services.
// If both account-ids and entitled-services are empty,
// then data for all entitled-services in all accounts are returned.
func (a *DefaultAuthorizer) GetAcctEntitlements(ctx context.Context, accountIDs, serviceNames []string) (*AcctEntitlementsType, error) {
	lgNtry := ctxlogrus.Extract(ctx)
	acctResult := AcctEntitlementsApiResult{}

	if accountIDs == nil {
		accountIDs = []string{}
	}
	if serviceNames == nil {
		serviceNames = []string{}
	}

	opaReq := opautil.OPARequest{
		Input: &AcctEntitlementsApiInput{
			AccountIDs:   accountIDs,
			ServiceNames: serviceNames,
		},
	}

	err := a.clienter.CustomQuery(ctx, a.acctEntitlementsApi, opaReq, &acctResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_acct_entitlements_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"acctResult": fmt.Sprintf("%#v", acctResult),
	}).Trace("get_acct_entitlements_okay")

	return acctResult.Result, nil
}
