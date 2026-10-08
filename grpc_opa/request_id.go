package grpc_opa_middleware

import (
	"context"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
)

// --- splitting this specific functionality out from
// https://github.com/infobloxopen/atlas-app-toolkit/blob/master/requestid/requestid.go
// and
// https://github.com/infobloxopen/atlas-app-toolkit/blob/master/gateway/header.go
// to avoid that dependency chain for such a minor feature

// Declaring RequestIDHeaderKeys as a mutable list so it can
// be overwritten or additional options appended.
// Items are checked in order, so the first options are higher
// priority if multiple matching headers are present
var (
	RequestIDHeaderKeys = []string{
		"X-Request-ID",
		"Request-Id",
	}
)

// RequestIDFromContext returns the Request-Id information from ctx if it exists in
// any of the RequestIDHeaderKeys headers from the GRPC metadata
func RequestIDFromContext(ctx context.Context) (string, bool) {
	if smd, ok := runtime.ServerMetadataFromContext(ctx); ok {
		ctx = metadata.NewIncomingContext(ctx, smd.HeaderMD)
	}

	imd, iok := metadata.FromIncomingContext(ctx)
	omd, ook := metadata.FromOutgoingContext(ctx)

	if !iok && !ook {
		return "", false
	}

	md := metadata.Join(imd, omd)

	for _, k := range RequestIDHeaderKeys {
		key := strings.ToLower(k)
		if v, ok := md[key]; ok && len(v) > 0 {
			return v[0], true
		}
		// Also check 'runtime.MetadataPrefix + key'
		// = grpcgateway-{key}
		key = runtime.MetadataPrefix + key
		if v, ok := md[key]; ok && len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}
