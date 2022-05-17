package opasdk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
)

// Override to set your servicename
var (
	SERVICENAME = "opa"
)

// startSpan enables tracing
func startSpan(ctx context.Context, log *logrus.Entry, input *InputPayload) (context.Context, *trace.Span, error) {
	js, err := json.Marshal(input)
	if err != nil {
		log.WithError(err).Errorf("JSON_marshal_error: %v", err)
		return ctx, nil, ErrInvalidArg
	}

	// To enable tracing, the context must have a tracer attached
	// to it. See the tracing documentation on how to do this.
	ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, input.FullMethod))
	span.Annotate([]trace.Attribute{
		trace.StringAttribute("in", string(js)),
	}, "in")
	// FIXME: perhaps only inject these fields if this is the default handler
	return ctx, span, nil
}

// endSpan stops tracing
func endSpan(span *trace.Span, err error) {
	// opencensus Status is based on gRPC status codes
	// https://pkg.go.dev/go.opencensus.io/trace?tab=doc#Status
	// err == nil will return {Code: 200, Message:""}
	span.SetStatus(trace.Status{
		Code:    int32(grpc.Code(err)),
		Message: grpc.ErrorDesc(err),
	})
	span.End()
}
