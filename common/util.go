package common

import "strings"

func RedactJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) > 0 {
		parts[len(parts)-1] = REDACTED
	}
	return strings.Join(parts, ".")
}

func RedactJWTForDebug(jwt string) string {
	parts := strings.Split(jwt, ".")
	// Redact signature, header and body since we do not want to display any for debug logging
	for i := range parts {
		parts[i] = parts[i][:Min(len(parts[i]), 16)] + "/" + REDACTED
	}
	return strings.Join(parts, ".")
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
