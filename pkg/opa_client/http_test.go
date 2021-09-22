package opa_client_test

import (
	"context"
	"errors"
	"io/ioutil"
	"syscall"
	"testing"

	opamw "github.com/infobloxopen/atlas-authz-middleware/grpc_opa"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)


func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestRestAPI(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	cli := utils_test.StartOpa(ctx, t, done)

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	if err := cli.Health(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionRefused(t *testing.T) {

	cli := opa_client.New("http://localhost:0001")
	err := cli.Health()
	if err == nil {
		t.Error("unexpected nil err")
	}

	if _, ok := err.(*opa_client.ErrorV1); !ok {
		t.Errorf("unexpected unstructured error: %#v", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("\ngot:    %#v\nwanted: %#v", err, syscall.ECONNREFUSED)
	}
}

// Verify that legal Rego set values (eg: "{1,2,3}") are returned as
// legal JSON array values (eg: "[1,2,3]") by OPA REST API
func TestPolicyReturningRegoSet(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(logrus.StandardLogger()))

	done := make(chan struct{})
	clienter := utils_test.StartOpa(ctx, t, done)
	cli, ok := clienter.(*opa_client.Client)
	if !ok {
		t.Fatal("Unable to convert interface to (*Client)")
		return
	}

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	policyRego, err := ioutil.ReadFile("testdata/policy_returning_set.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "mypolicyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	mockDecInp := &MockDecisionInputer{}
	auther := opamw.NewDefaultAuthorizer("app",
		opamw.WithOpaClienter(cli),
		opamw.WithDecisionInputHandler(mockDecInp),
		opamw.WithClaimsVerifier(utils_test.NullClaimsVerifier),
	)

	// If authorization is permitted, then this verifies that the OPA JSON results were correctly decoded,
	// and this verifies that the rego set result is returned by OPA as a JSON array result.
	resultCtx, resultErr := auther.AffirmAuthorization(ctx, "FakeMethod", nil)
	if resultErr != nil {
		t.Errorf("AffirmAuthorization err: %#v", resultErr)
	}
	if resultCtx == nil {
		t.Error("AffirmAuthorization returned nil context")
	}
}

type MockDecisionInputer struct{}

func (m MockDecisionInputer) String() string {
	return "opa_client_test.MockDecisionInputer{}"
}

func (m *MockDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*opamw.DecisionInput, error) {
	decInp := opamw.DecisionInput{
		DecisionDocument: "/v1/data/policy_returning_set/get_results",
	}
	return &decInp, nil
}
