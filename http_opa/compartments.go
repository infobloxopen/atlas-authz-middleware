package httpopa

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/v2/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/opautil"
	atlas_claims "github.com/infobloxopen/atlas-claims"
	logrus "github.com/sirupsen/logrus"
)

// CurrentUserCompartmentsResult is the data type json.Unmarshaled from OPA RESTAPI query
// to current_user_compartments rego rule
type CurrentUserCompartmentsResult struct {
	Result []string `json:"result"`
}

// GetCurrentUserCompartments returns list of compartment-ids
// for the current-user's JWT in the context.
func (a *httpAuthorizer) GetCurrentUserCompartments(ctx context.Context) ([]string, error) {
	lgNtry := ctxlogrus.Extract(ctx)
	cptResult := CurrentUserCompartmentsResult{}

	// This fetches auth data from auth headers in metadata from context:
	// bearer = data from "authorization bearer" metadata header
	// newBearer = data from "set-authorization bearer" metadata header
	bearer, newBearer := atlas_claims.AuthBearersFromCtx(ctx)

	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = commonClaim.UnverifiedClaimFromBearers
	}

	rawJWT, errs := claimsVerifier([]string{bearer}, []string{newBearer})
	if len(errs) > 0 {
		return nil, fmt.Errorf("%q", errs)
	}

	opaReq := opautil.OPARequest{
		Input: &opautil.Payload{
			JWT: opautil.RedactJWT(rawJWT),
		},
	}

	err := a.clienter.CustomQuery(ctx, a.currUserCompartmentsApi, opaReq, &cptResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_curr_user_compartments_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"cptResult": fmt.Sprintf("%#v", cptResult),
	}).Trace("get_curr_user_compartments_okay")

	return cptResult.Result, nil
}
