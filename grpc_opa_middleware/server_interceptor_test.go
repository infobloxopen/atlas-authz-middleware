package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
)

var netDialErr = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

type connFailTransport struct {
	req *http.Request
}

func (t *connFailTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	t.req = req
	return nil, netDialErr
}

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func nullClaimsVerifier([]string, []string) (string, []error) {
	return "", nil
}

func TestConnFailure(t *testing.T) {
	claimsVerifier = nullClaimsVerifier

	grpcUnaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}
	interceptor := UnaryServerInterceptor("app", WithHTTPClient(&http.Client{
		Transport: &connFailTransport{},
	}))

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(3*time.Second))
	defer cancel()
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "FakeMethod"}, grpcUnaryHandler)
	if resp != nil {
		t.Errorf("unexpected resp: %#v", resp)
	}

	if e := opa_client.ErrServiceUnavailable; !errors.Is(err, e) {
		t.Errorf("got: %s wanted: %s", err, e)
	}
}

func TestMockOPA(t *testing.T) {
	claimsVerifier = nullClaimsVerifier

	grpcUnaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}

	mock := new(mockAuthorizer)
	interceptor := UnaryServerInterceptor("app", WithAuthorizer(mock))

	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	testMap := []struct {
		code   codes.Code
		fn     AuthorizeFn
		errMsg string
	}{
		{
			code: codes.Internal,
			fn: func(ctx context.Context, fullMethodName string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
				return false, ctx, grpc.Errorf(codes.Internal, "boom")
			},
			errMsg: "boom",
		},
	}

	for _, tm := range testMap {
		mock.evaluate = tm.fn
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "FakeMethod"}, grpcUnaryHandler)
		if e := tm.code; e != grpc.Code(err) {
			t.Errorf("got: %s wanted: %s", grpc.Code(err), e)
		}
		if e := tm.errMsg; e != grpc.ErrorDesc(err) {
			t.Errorf("got: %s wanted: %s", err, e)
		}
	}
}

type mockAuthorizer struct {
	DefaultAuthorizer
	evaluate func(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error)
}

func (m *mockAuthorizer) Evaluate(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return m.evaluate(ctx, fullMethod, opaEvaluator)
}

func TestStreamServerInterceptor(t *testing.T) {
	claimsVerifier = nullClaimsVerifier

	grpcStreamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	mock := new(mockAuthorizer)
	interceptor := StreamServerInterceptor("app", WithAuthorizer(mock))

	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	testMap := []struct {
		code   codes.Code
		fn     AuthorizeFn
		errMsg string
	}{
		{
			code: codes.Internal,
			fn: func(ctx context.Context, fullMethodName string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
				return false, ctx, grpc.Errorf(codes.Internal, "boom")
			},
			errMsg: "boom",
		},
	}

	srvStream := WrappedSrvStream{
		WrappedCtx: context.Background(),
	}

	for _, tm := range testMap {
		mock.evaluate = tm.fn
		err := interceptor(ctx, &srvStream, &grpc.StreamServerInfo{FullMethod: "FakeMethod"}, grpcStreamHandler)

		if e := tm.code; e != grpc.Code(err) {
			t.Errorf("got: %s wanted: %s", grpc.Code(err), e)
		}
		if e := tm.errMsg; e != grpc.ErrorDesc(err) {
			t.Errorf("got: %s wanted: %s", err, e)
		}
	}
}

type mockAuthorizerWithAllowOpaEvaluator struct {
	defAuther *DefaultAuthorizer
}

func (a *mockAuthorizerWithAllowOpaEvaluator) Evaluate(ctx context.Context, fullMethod string, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return a.defAuther.Evaluate(ctx, fullMethod, opaEvaluator)
}

func (m *mockAuthorizerWithAllowOpaEvaluator) OpaQuery(ctx context.Context, decisionDocument string, req, resp interface{}) error {
	return json.Unmarshal([]byte(`{"allow": true}`), resp)
}

func newMockAuthorizerWithAllowOpaEvaluator(application string, opts ...Option) *mockAuthorizerWithAllowOpaEvaluator {
	a := new(mockAuthorizerWithAllowOpaEvaluator)
	a.defAuther = NewDefaultAuthorizer(application, opts...)
	return a
}

type badDecisionInputer struct{}

func (m *badDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string) (*DecisionInput, error) {
	return nil, fmt.Errorf("badDecisionInputer")
}

type jsonMarshalableInputer struct{}

func (m *jsonMarshalableInputer) GetDecisionInput(ctx context.Context, fullMethod string) (*DecisionInput, error) {
	var sealctx []interface{}
	sealctx = append(sealctx, map[string]interface{}{
		"id":   "guid1",
		"name": "ClassA",
		"tags": map[string]string{
			"dept": "finance",
			"zone": "apj",
		},
	})
	sealctx = append(sealctx, map[string]interface{}{
		"id":   "guid2",
		"name": "ClassB",
		"tags": map[string]string{
			"dept": "sales",
			"zone": "emea",
		},
	})

	inp, _ := defDecisionInputer.GetDecisionInput(ctx, fullMethod)
	inp.SealCtx = sealctx

	//logrus.Debugf("inp=%+v", *inp)
	return inp, nil
}

type jsonNonMarshalableInputer struct{}

func (m *jsonNonMarshalableInputer) GetDecisionInput(ctx context.Context, fullMethod string) (*DecisionInput, error) {
	var sealctx []interface{}
	sealctx = append(sealctx, nullClaimsVerifier) // nullClaimsVerifier is a non-json-marshalable fn)

	inp, _ := defDecisionInputer.GetDecisionInput(ctx, fullMethod)
	inp.SealCtx = sealctx
	//logrus.Debugf("inp=%+v", *inp)
	return inp, nil
}

func TestDecisionInput(t *testing.T) {
	claimsVerifier = nil

	testMap := []struct {
		err       error
		abacType  string
		abacVerb  string
		inputer   DecisionInputHandler
		jwtHeader string
	}{
		{
			err:      nil,
			abacType: "electron",
			abacVerb: "run",
			inputer:  new(jsonMarshalableInputer),
			// fake jwt with fake signature
			jwtHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJvZ3VzQGZvby5jb20iLCJhcGlfdG9rZW4iOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImFjY291bnRfaWQiOiI0MDQiLCJncm91cHMiOlsiZm9vX2FkbWluIiwiYWRtaW4iXSwiYXVkIjoiZm9vLWF1ZGllbmNlIiwiZXhwIjoyMzk4MzY3NTQwLCJpYXQiOjE1MzQzNjc1NDAsImlzcyI6ImZvby1pc3N1ZXIiLCJuYmYiOjE1MzQzNjc1NDB9.fhwZBaz7TkRbcPcM1M_l1B_S1UZSvro3jwc4EhV37IA",
		},
		{
			err:      ErrInvalidArg,
			abacType: "proton",
			abacVerb: "jump",
			inputer:  new(jsonNonMarshalableInputer),
			// fake svc-svc jwt with fake signature
			jwtHeader: "bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoiZm9vLXNlcnZpY2UiLCJhdWQiOiJmb28tYXVkaWVuY2UiLCJleHAiOjIzOTg4NzI3NzgsImp0aSI6ImZvby1qdGkiLCJpYXQiOjE1MzUzMjE0MDcsImlzcyI6ImZvby1pc3N1ZXIiLCJuYmYiOjE1MzUzMjE0MDd9.4zcNzRrhIXN3s6jNYWIbe6TRBaOwTh_Yy1iSCqVW9H4pT3p2c23TSsLq6R2zs-xmsZ5jTUvalpQgPJwbFmdvxA",
		},
		{
			err:      ErrInvalidArg,
			abacType: "neutron",
			abacVerb: "swim",
			inputer:  new(badDecisionInputer),
			// empty jwt with fake signature
			jwtHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.A5mVf-_pE0XM6RlWnNx4YBzFWqYIcsc3_j1g9I2768c",
		},
	}

	for _, tm := range testMap {
		grpcUnaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, nil
		}

		mockInputer := tm.inputer
		mockAuthzer := newMockAuthorizerWithAllowOpaEvaluator("myapplication", WithDecisionInputHandler(mockInputer))
		interceptor := UnaryServerInterceptor("app", WithAuthorizer(mockAuthzer), WithDecisionInputHandler(mockInputer))

		headers := map[string]string{
			"authorization": tm.jwtHeader,
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, TypeKey, tm.abacType)
		ctx = context.WithValue(ctx, VerbKey, tm.abacVerb)
		ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(logrus.StandardLogger()))
		ctx = metadata.NewIncomingContext(ctx, metadata.New(headers))

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "FakeService.FakeMethod"}, grpcUnaryHandler)
		//t.Logf("err=%+v tm.err=%+v", err, tm.err)
		if err != tm.err {
			t.Errorf("got: %s wanted: %s", err, tm.err)
		}
	}
}
