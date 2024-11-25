package httpopa

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/v2/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/opautil"
	atlas_claims "github.com/infobloxopen/atlas-claims"
	logrus "github.com/sirupsen/logrus"
)

// FilterCompartmentPermissionsInput is the input payload for filter_compartment_permissions_api
type FilterCompartmentPermissionsInput struct {
	JWT         string                              `json:"jwt"`
	Permissions az.FilterCompartmentPermissionsType `json:"permissions"`
}

// FilterCompartmentPermissionsResult is the data type json.Unmarshaled from OPA RESTAPI query
// to filter_compartment_permissions_api rego rule
type FilterCompartmentPermissionsResult struct {
	Result az.FilterCompartmentPermissionsType `json:"result"`
}

// FilterCompartmentPermissions filters list of permissions based on the JWT in the context
func (a *httpAuthorizer) FilterCompartmentPermissions(ctx context.Context, permissions az.FilterCompartmentPermissionsType) (az.FilterCompartmentPermissionsType, error) {
	lgNtry := ctxlogrus.Extract(ctx)
	permsResult := FilterCompartmentPermissionsResult{}

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
		Input: &FilterCompartmentPermissionsInput{
			JWT:         opautil.RedactJWT(rawJWT),
			Permissions: permissions,
		},
	}

	err := a.clienter.CustomQuery(ctx, a.filterCompartmentPermsApi, opaReq, &permsResult)
	if err != nil {
		lgNtry.WithError(err).Error("filter_compartment_permissions_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"permsResult": fmt.Sprintf("%#v", permsResult),
	}).Trace("filter_compartment_permissions_okay")

	return permsResult.Result, nil
}

// FilterCompartmentFeaturesInput is the input payload for filter_compartment_features_api
type FilterCompartmentFeaturesInput struct {
	JWT                 string                           `json:"jwt"`
	ApplicationFeatures az.FilterCompartmentFeaturesType `json:"application_features"`
}

// FilterCompartmentFeaturesResult is the data type json.Unmarshaled from OPA RESTAPI query
// to filter_compartment_features_api rego rule
type FilterCompartmentFeaturesResult struct {
	Result az.FilterCompartmentFeaturesType `json:"result"`
}

// FilterCompartmentFeatures filters list of features based on the JWT in the context
func (a *httpAuthorizer) FilterCompartmentFeatures(ctx context.Context, features az.FilterCompartmentFeaturesType) (az.FilterCompartmentFeaturesType, error) {
	lgNtry := ctxlogrus.Extract(ctx)
	featsResult := FilterCompartmentFeaturesResult{}

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
		Input: &FilterCompartmentFeaturesInput{
			JWT:                 opautil.RedactJWT(rawJWT),
			ApplicationFeatures: features,
		},
	}

	err := a.clienter.CustomQuery(ctx, a.filterCompartmentFeatsApi, opaReq, &featsResult)
	if err != nil {
		lgNtry.WithError(err).Error("filter_compartment_features_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"featsResult": fmt.Sprintf("%#v", featsResult),
	}).Trace("filter_compartment_features_okay")

	return featsResult.Result, nil
}
