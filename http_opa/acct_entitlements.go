package httpopa

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/opautil"
	logrus "github.com/sirupsen/logrus"
)

// AcctEntitlementsApiInput is the input payload for acct_entitlements_api
type AcctEntitlementsApiInput struct {
	AccountIDs   []string `json:"acct_entitlements_acct_ids"`
	ServiceNames []string `json:"acct_entitlements_services"`
}

// AcctEntitlementsApiResult is the data type json.Unmarshaled from OPA RESTAPI query to acct_entitlements_api
type AcctEntitlementsApiResult struct {
	Result *az.AcctEntitlementsType `json:"result"`
}

// GetAcctEntitlements queries account entitled features data
// for the specified account-ids and entitled-services.
// If both account-ids and entitled-services are empty,
// then data for all entitled-services in all accounts are returned.
func (a *httpAuthorizer) GetAcctEntitlements(ctx context.Context, accountIDs, serviceNames []string) (*az.AcctEntitlementsType, error) {
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
