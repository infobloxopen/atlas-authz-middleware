package grpc_opa_middleware

import (
	atlas_claims "github.com/infobloxopen/atlas-claims"
)

// NullClaimsVerifier does nothing and just returns non-error empty bearer string.
func NullClaimsVerifier([]string, []string) (string, []error) {
	return "", nil
}

// UnverifiedClaimFromBearers parses JWT claims from 'bearer' and 'newBearer' strings,
// and returns the chosen valid bearer string ('newBearer' has precedence over 'bearer').
// It is similar to atlas_claims.UnverifiedClaimFromBearers(),
// but returns the chosen raw bearer string instead of the decoded claims.
// (https://github.com/infobloxopen/atlas-claims/blob/c116bfcdadb14433dcd41c771b9755f7f640da33/parser.go#L36)
// None of the claims are checked, including IssuedAt(iat), NotBefore(nbf), nor ExpiresAt(exp) claims.
// The signature is also not checked.
// Returns error if bearer strings are not valid JWT (eg: empty bearer string is invalid).
func UnverifiedClaimFromBearers(bearer, newBearer []string) (string, []error) {
	_, validBearer, bearerErrorList := atlas_claims.ParseUnverifiedClaimsFromJwtStringsRaw(bearer)
	_, validNewBearer, newBearerErrorList := atlas_claims.ParseUnverifiedClaimsFromJwtStringsRaw(newBearer)
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
