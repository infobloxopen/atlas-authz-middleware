package grpc_opa_middleware

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"google.golang.org/grpc"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
)

const (
	authZKey = key("grpc-authz-key")
)

var (
	// Application is set at initization
	Application      string
	ErrNoCredentials = errors.New("no credentials found")
)

type key string

// UnaryServerInterceptor returns a new unary client interceptor that optionally logs the execution of external gRPC calls.
func UnaryServerInterceptor(application string, opts ...Option) grpc.UnaryServerInterceptor {
	cfg := NewAuthorizationConfigUnary(application, opts...)

	return func(ctx context.Context, grpcReq interface{}, info *grpc.UnaryServerInfo, grpcUnaryHandler grpc.UnaryHandler) (interface{}, error) {
		newCtx, err := AffirmAuthorizationUnary(ctx, cfg, info.FullMethod, grpcReq)
		if newCtx == nil || err != nil {
			return newCtx, err
		}

		// TODO: pass along authz information through context
		return grpcUnaryHandler(newCtx, grpcReq)
	}
}

// StreamServerInterceptor returns a new Stream client interceptor that optionally logs the execution of external gRPC calls.
func StreamServerInterceptor(application string, opts ...Option) grpc.StreamServerInterceptor {

	cfg := &Config{
		address: opa_client.DefaultAddress,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.authorizer == nil {
		cfg.authorizer = []Authorizer{&DefaultAuthorizer{
			clienter:    opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli)),
			application: application,
		}}
	}

	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, grpcStreamHandler grpc.StreamHandler) error {
		logger := ctxlogrus.Extract(stream.Context())

		var (
			ok     bool
			newCtx context.Context
			err    error
		)

		for _, auther := range cfg.authorizer {
			ok, newCtx, err = auther.Evaluate(stream.Context(), info.FullMethod, info, auther.OpaQuery)
			if err != nil {
				logger.WithError(err).Error("unable_authorize")
			}
			if ok {
				break
			}
		}

		if err != nil {
			return err
		}

		if !ok {
			logger.WithError(opa_client.ErrUndefined).Error("policy engine returned undefined response")
			return opa_client.ErrUndefined
		}

		// TODO: pass along authz information through context
		wrapped := wrapServerStream(stream)
		wrapped.WrappedCtx = newCtx
		return grpcStreamHandler(srv, wrapped)
	}
}

// FromContext retrieves authZ information from the Context
func FromContext(ctx context.Context) interface{} {
	return ctx.Value(authZKey)
}

// WrappedSrvStream allows modifying context.
type WrappedSrvStream struct {
	grpc.ServerStream
	// It is wrapper's own Context.
	WrappedCtx context.Context
}

// Context returns the wrapper's WrappedCtx
func (w *WrappedSrvStream) Context() context.Context {
	return w.WrappedCtx
}

// wrapServerStream returns a ServerStream that has the ability to overwrite context.
func wrapServerStream(stream grpc.ServerStream) *WrappedSrvStream {
	if existing, ok := stream.(*WrappedSrvStream); ok {
		return existing
	}
	return &WrappedSrvStream{ServerStream: stream, WrappedCtx: stream.Context()}
}
