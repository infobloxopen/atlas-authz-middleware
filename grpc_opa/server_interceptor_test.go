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
	logrustesthook "github.com/sirupsen/logrus/hooks/test"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
)

var netDialErr = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

type connFailTransport struct {
	httpReq *http.Request
}

func (t *connFailTransport) RoundTrip(httpReq *http.Request) (httpResp *http.Response, err error) {
	t.httpReq = httpReq
	return nil, netDialErr
}

func init() {
	logrus.SetLevel(logrus.TraceLevel)
}

func TestConnFailure(t *testing.T) {
	grpcUnaryHandler := func(ctx context.Context, grpcReq interface{}) (interface{}, error) {
		return nil, nil
	}
	interceptor := UnaryServerInterceptor("app",
		WithHTTPClient(&http.Client{Transport: &connFailTransport{},}),
		WithClaimsVerifier(NullClaimsVerifier),
	)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(3*time.Second))
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	defer cancel()
	grpcResp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "FakeMethod"}, grpcUnaryHandler)
	if grpcResp != nil {
		t.Errorf("unexpected grpcResp: %#v", grpcResp)
	}

	if e := opa_client.ErrServiceUnavailable; !errors.Is(err, e) {
		t.Errorf("got: %s wanted: %s", err, e)
	}
}

func TestMockOPA(t *testing.T) {
	grpcUnaryHandler := func(ctx context.Context, grpcReq interface{}) (interface{}, error) {
		return nil, nil
	}

	mock := new(mockAuthorizer)
	interceptor := UnaryServerInterceptor("app",
		WithAuthorizer(mock),
		WithClaimsVerifier(NullClaimsVerifier),
	)

	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	defer cancel()
	testMap := []struct {
		code   codes.Code
		fn     AuthorizeFn
		errMsg string
	}{
		{
			code: codes.Internal,
			fn: func(ctx context.Context, fullMethodName string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
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
	evaluate func(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error)
}

func (m *mockAuthorizer) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return m.evaluate(ctx, fullMethod, grpcReq, opaEvaluator)
}

func TestStreamServerInterceptorMockAuthorizer(t *testing.T) {
	grpcStreamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	mock := new(mockAuthorizer)
	interceptor := StreamServerInterceptor("app",
		WithAuthorizer(mock),
		WithClaimsVerifier(NullClaimsVerifier),
	)

	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	defer cancel()
	testMap := []struct {
		code   codes.Code
		fn     AuthorizeFn
		errMsg string
	}{
		{
			code: codes.Internal,
			fn: func(ctx context.Context, fullMethodName string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
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

func (m mockAuthorizerWithAllowOpaEvaluator) String() string {
	return fmt.Sprintf("mockAuthorizerWithAllowOpaEvaluator{defAuther:%s}", m.defAuther.String())
}

func (a *mockAuthorizerWithAllowOpaEvaluator) Validate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (interface{}, error) {
	return a.defAuther.Validate(ctx, fullMethod, grpcReq, opaEvaluator)
}

func (a *mockAuthorizerWithAllowOpaEvaluator) Evaluate(ctx context.Context, fullMethod string, grpcReq interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	return a.defAuther.Evaluate(ctx, fullMethod, grpcReq, opaEvaluator)
}

func (m *mockAuthorizerWithAllowOpaEvaluator) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	t, _ := ctx.Value(utils_test.TestingTContextKey).(*testing.T)
	_, ok := opaReq.(Payload)
	allow := "true"
	if !ok {
		allow = "false"
		t.Errorf("invalid opa payload (type: %T)", opaReq)
	}
	respJSON := fmt.Sprintf(`{"allow": %s}`, allow)
	return json.Unmarshal([]byte(respJSON), opaResp)
}

func newMockAuthorizerWithAllowOpaEvaluator(application string, opts ...Option) *mockAuthorizerWithAllowOpaEvaluator {
	a := new(mockAuthorizerWithAllowOpaEvaluator)
	a.defAuther = NewDefaultAuthorizer(application, opts...)
	return a
}

type badDecisionInputer struct{}

func (m badDecisionInputer) String() string {
	return "badDecisionInputer{}"
}

func (m *badDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error) {
	return nil, fmt.Errorf("badDecisionInputer")
}

type jsonMarshalableInputer struct{}

func (m jsonMarshalableInputer) String() string {
	return "jsonMarshalableInputer{}"
}

func (m *jsonMarshalableInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error) {
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

	inp, _ := defDecisionInputer.GetDecisionInput(ctx, fullMethod, grpcReq)
	inp.SealCtx = sealctx

	//logrus.Debugf("inp=%+v", *inp)
	return inp, nil
}

type jsonNonMarshalableInputer struct{}

func (m jsonNonMarshalableInputer) String() string {
	return "jsonNonMarshalableInputer{}"
}

func (m *jsonNonMarshalableInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*DecisionInput, error) {
	var sealctx []interface{}
	sealctx = append(sealctx, NullClaimsVerifier) // NullClaimsVerifier is a non-json-marshalable fn)

	inp, _ := defDecisionInputer.GetDecisionInput(ctx, fullMethod, grpcReq)
	inp.SealCtx = sealctx
	//logrus.Debugf("inp=%+v", *inp)
	return inp, nil
}

func TestDecisionInput(t *testing.T) {
	testMap := []struct {
		err       error
		abacType  string
		abacVerb  string
		inputer   DecisionInputHandler
		jwtHeader string
		errLogMsg string
		authorizerField string
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
			errLogMsg: `unable_authorize`,
			authorizerField: `mockAuthorizerWithAllowOpaEvaluator{defAuther:grpc_opa_middleware.DefaultAuthorizer{application:"myapplication" clienter:opa_client.Client{address:"http://localhost:8181"} decisionInputHandler:jsonNonMarshalableInputer{}}}`,
		},
		{
			err:      ErrInvalidArg,
			abacType: "neutron",
			abacVerb: "swim",
			inputer:  new(badDecisionInputer),
			// empty jwt with fake signature
			jwtHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.A5mVf-_pE0XM6RlWnNx4YBzFWqYIcsc3_j1g9I2768c",
			errLogMsg: `unable_authorize`,
			authorizerField: `mockAuthorizerWithAllowOpaEvaluator{defAuther:grpc_opa_middleware.DefaultAuthorizer{application:"myapplication" clienter:opa_client.Client{address:"http://localhost:8181"} decisionInputHandler:badDecisionInputer{}}}`,
		},
	}

	loggertesthook := logrustesthook.NewGlobal()

	for nth, tm := range testMap {
		grpcUnaryHandler := func(ctx context.Context, grpcReq interface{}) (interface{}, error) {
			return nil, nil
		}

		mockInputer := tm.inputer
		mockAuthzer := newMockAuthorizerWithAllowOpaEvaluator("myapplication", WithDecisionInputHandler(mockInputer))
		interceptor := UnaryServerInterceptor("app",
			WithAuthorizer(mockAuthzer),
			WithDecisionInputHandler(mockInputer),
			WithClaimsVerifier(NullClaimsVerifier),
		)

		headers := map[string]string{
			"authorization": tm.jwtHeader,
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
		ctx = context.WithValue(ctx, TypeKey, tm.abacType)
		ctx = context.WithValue(ctx, VerbKey, tm.abacVerb)
		ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(logrus.StandardLogger()))
		ctx = metadata.NewIncomingContext(ctx, metadata.New(headers))

		loggertesthook.Reset()

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "FakeService.FakeMethod"}, grpcUnaryHandler)
		//t.Logf("err=%+v tm.err=%+v", err, tm.err)
		if err != tm.err {
			t.Errorf("%d: got: %s wanted: %s", nth, err, tm.err)
		} else if err != nil {
			gotExpectedErrLogMsg := false
			for _, entry := range loggertesthook.AllEntries() {
				t.Logf("%d: logrus.Entry.Message: %s", nth, entry.Message)
				t.Logf("%d: logrus.Entry.Data: %s", nth, entry.Data)
				authorizerFieldVal := entry.Data["authorizer"]
				authorizerField := fmt.Sprint(authorizerFieldVal)
				if entry.Message == tm.errLogMsg {
					if authorizerField == tm.authorizerField {
						gotExpectedErrLogMsg = true
					} else {
						t.Errorf("%d: Did not\n get authorizerField: `%s`\n got authorizerField: `%s`",
							nth, tm.authorizerField, authorizerField)
					}
					break
				}
			}
			if !gotExpectedErrLogMsg {
				t.Errorf("%d: Did not get logrus.Entry.Message: `%s`", nth, tm.errLogMsg)
			}
		}
	}
}

func TestStreamServerInterceptorMockOpaClient(t *testing.T) {
	testMap := []struct {
		regoRespJSON string
		expErr       error
	}{
		{
			regoRespJSON: `{"allow": false, "obligations": {}}`,
			expErr:       ErrForbidden,
		},
		{
			regoRespJSON: `{"allow": true, "obligations": {}}`,
			expErr:       nil,
		},
		{
			regoRespJSON: `invalid json result`,
			expErr:       opa_client.ErrUnknown,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	srvStream := WrappedSrvStream{
		WrappedCtx: ctx,
	}

	grpcStreamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	for idx, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoRespJSON,
		}
		interceptor := StreamServerInterceptor("app",
			WithOpaClienter(mockOpaClienter),
			WithClaimsVerifier(NullClaimsVerifier),
		)

		gotErr := interceptor(ctx, &srvStream,
			&grpc.StreamServerInfo{FullMethod: "FakeMethod"},
			grpcStreamHandler)
		t.Logf("%d: gotErr=%s", idx, gotErr)

		if (tm.expErr == nil) && gotErr != nil {
			t.Errorf("%d: expErr=nil, gotErr=%s", idx, gotErr)
		} else if (tm.expErr != nil) && (tm.expErr != gotErr) {
			t.Errorf("%d: expErr=%s, gotErr=%s", idx, tm.expErr, gotErr)
		}
	}
}
