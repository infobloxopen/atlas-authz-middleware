package opa_client_test

import (
	"context"
	"errors"
	"io/ioutil"
	"reflect"
	"syscall"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/claim"
	opamw "github.com/infobloxopen/atlas-authz-middleware/v2/grpc_opa"
	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/v2/utils_test"

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
	err = cli.UploadRegoPolicy(ctx, "policy_returning_set_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	mockDecInp := &MockDecisionInputer{}
	auther := opamw.NewDefaultAuthorizer("app",
		opamw.WithOpaClienter(cli),
		opamw.WithDecisionInputHandler(mockDecInp),
		opamw.WithClaimsVerifier(claim.NullClaimsVerifier),
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

func TestCustomQuery(t *testing.T) {
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

	policyRego, err := ioutil.ReadFile("testdata/custom_query_test.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "custom_query_test_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	opaQry := "v1/data/custom_query_test/map_map_arr"

	expectBytes := `{"result":{"2001016":{"hardware":["hdd4tb","ram32mb"],"laptop":["lenovo"],"software":["msoffice","visualstudio"]},"2001040":{"hardware":["ram64mb","ssd1tb"],"laptop":["apple"],"software":["msoffice","photoshop"]}}}`

	actualBytes, err := cli.CustomQueryBytes(ctx, opaQry, nil)
	if err != nil {
		t.Errorf("CustomQueryBytes FAIL: err=%#v", err)
	}
	t.Logf("actualBytes=%s", actualBytes)

	if expectBytes != string(actualBytes) {
		t.Errorf("CustomQueryBytes FAIL\nexpectBytes=%s\nactualBytes=%s",
			expectBytes, actualBytes)
	}

	type typeGeneric map[string]interface{}
	expectGeneric := typeGeneric{
		"result": map[string]interface{}{
			"2001016": map[string]interface{}{
				"hardware": []interface{}{"hdd4tb", "ram32mb"},
				"laptop":   []interface{}{"lenovo"},
				"software": []interface{}{"msoffice", "visualstudio"},
			},
			"2001040": map[string]interface{}{
				"hardware": []interface{}{"ram64mb", "ssd1tb"},
				"laptop":   []interface{}{"apple"},
				"software": []interface{}{"msoffice", "photoshop"},
			},
		},
	}

	var actualGeneric typeGeneric
	err = cli.CustomQuery(ctx, opaQry, nil, &actualGeneric)
	if err != nil {
		t.Errorf("CustomQuery(Generic) FAIL: err=%#v", err)
	}
	t.Logf("actualGeneric=%#v", actualGeneric)

	if !reflect.DeepEqual(expectGeneric, actualGeneric) {
		t.Errorf("CustomQuery(Generic) FAIL\nexpectGeneric=%#v\nactualGeneric=%#v",
			expectGeneric, actualGeneric)
	}

	type typeSpecific map[string]map[string]map[string][]string
	expectSpecific := typeSpecific{
		"result": {
			"2001016": {
				"hardware": {"hdd4tb", "ram32mb"},
				"laptop":   {"lenovo"},
				"software": {"msoffice", "visualstudio"},
			},
			"2001040": {
				"hardware": {"ram64mb", "ssd1tb"},
				"laptop":   {"apple"},
				"software": {"msoffice", "photoshop"},
			},
		},
	}

	var actualSpecific typeSpecific
	err = cli.CustomQuery(ctx, opaQry, nil, &actualSpecific)
	if err != nil {
		t.Errorf("CustomQuery(Specific) FAIL: err=%#v", err)
	}
	t.Logf("actualSpecific=%#v", actualSpecific)

	if !reflect.DeepEqual(expectSpecific, actualSpecific) {
		t.Errorf("CustomQuery(Specific) FAIL\nexpectSpecific=%#v\nactualSpecific=%#v",
			expectSpecific, actualSpecific)
	}
}

type MockDecisionInputer struct{}

func (m MockDecisionInputer) String() string {
	return "opa_client_test.MockDecisionInputer{}"
}

func (m *MockDecisionInputer) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*authorizer.DecisionInput, error) {
	decInp := authorizer.DecisionInput{
		DecisionDocument: "/v1/data/policy_returning_set/get_results",
	}
	return &decInp, nil
}
