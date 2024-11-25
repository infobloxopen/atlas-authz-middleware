package utils_test

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc/metadata"
)

// ContextWithJWT adds JWT as authorization-bearer token to context, returning the new context.
// From https://github.com/grpc-ecosystem/go-grpc-middleware/blob/master/auth/metadata_test.go
func ContextWithJWT(ctx context.Context, jwtStr string) context.Context {
	bearerStr := fmt.Sprintf(`bearer %s`, jwtStr)
	md := metadata.Pairs(`authorization`, bearerStr)
	ctx = metautils.NiceMD(md).ToIncoming(ctx)
	return ctx
}
