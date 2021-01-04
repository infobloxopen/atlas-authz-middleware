package grpc_opa_middleware

import (
	athena_claims "github.com/infobloxopen/atlas-claims"
)

// athena-authn_claims.UnverifiedClaimFromBearers
func UnverifiedClaimFromBearers(bearer, newBearer []string) (string, []error) {
	_, validBearer, bearerErrorList := athena_claims.ParseUnverifiedClaimsFromJwtStringsRaw(bearer)
	_, validNewBearer, newBearerErrorList := athena_claims.ParseUnverifiedClaimsFromJwtStringsRaw(newBearer)
	if len(newBearerErrorList) > 0 || len(bearerErrorList) > 0 {
		//fishy Should not have multiple newBearers
	}
	// Take the new bearer if possible.
	if len(validNewBearer) > 0 {
		return validNewBearer, nil
	} else if len(validBearer) > 0 {
		return validBearer, nil
	}

	return "", append(bearerErrorList, newBearerErrorList...)
}
