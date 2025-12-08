package opa_client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"reflect"
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
	err = cli.UploadRegoPolicy(ctx, "policy_returning_set_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	mockDecInp := &MockDecisionInputer{}
	auther := opamw.NewDefaultAuthorizer("app",
		opamw.WithOpaClienter(cli),
		opamw.WithDecisionInputHandler(mockDecInp),
		opamw.WithClaimsVerifier(opamw.NullClaimsVerifier),
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

	// If OPA POST request body does NOT contain 'input' key,
	// OPA will now add api_usage_warning "'input key' missing from the request"
	// to the OPA POST response.
	// This warning was added to OPA in v0.39.0:
	// https://github.com/open-policy-agent/opa/releases/tag/v0.39.0
	// https://github.com/open-policy-agent/opa/issues/4386
	// https://github.com/open-policy-agent/opa/pull/4416

	opaQry := "v1/data/custom_query_test/map_map_arr"

	////////////////////////////////////////////////////////////////

	expectBytes := `{"result":{"2001016":{"hardware":["hdd4tb","ram32mb"],"laptop":["lenovo"],"software":["msoffice","visualstudio"]},"2001040":{"hardware":["ram64mb","ssd1tb"],"laptop":["apple"],"software":["msoffice","photoshop"]}},"warning":{"code":"api_usage_warning","message":"'input' key missing from the request"}}
`

	actualBytes, err := cli.CustomQueryBytes(ctx, opaQry, nil)
	if err != nil {
		t.Errorf("CustomQueryBytes FAIL: err=%#v", err)
	}
	t.Logf("actualBytes=`%s`", actualBytes)

	if expectBytes != string(actualBytes) {
		t.Errorf("CustomQueryBytes FAIL\nexpectBytes=`%s`\nactualBytes=`%s`",
			expectBytes, actualBytes)
	}

	////////////////////////////////////////////////////////////////

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
		"warning": map[string]interface{}{
			"code":    "api_usage_warning",
			"message": "'input' key missing from the request",
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

	////////////////////////////////////////////////////////////////

	type typeSpecific1 map[string]map[string]map[string][]string
	expectSpecific1 := typeSpecific1{
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
		"warning": {
			"code": nil,
			"message": nil,
		},
	}

	var actualSpecific1 typeSpecific1
	err = cli.CustomQuery(ctx, opaQry, nil, &actualSpecific1)
	var jsonErr *json.UnmarshalTypeError
	if !errors.As(err, &jsonErr) {
		// We expect the OPA warning field to fail json-unmarshaling into typeSpecific1
		t.Errorf("CustomQuery(Specific1) FAIL: expected json.UnmarshalTypeError, but got: err=%#v", err)
	}
	t.Logf("actualSpecific1=%#v", actualSpecific1)

	if !reflect.DeepEqual(expectSpecific1, actualSpecific1) {
		t.Errorf("CustomQuery(Specific1) FAIL\nexpectSpecific1=%#v\nactualSpecific1=%#v",
			expectSpecific1, actualSpecific1)
	}

	////////////////////////////////////////////////////////////////

	type typeSpecific2 struct {
		Result  map[string]map[string][]string `json:"result"`
	}
	expectSpecific2 := typeSpecific2{
		Result: map[string]map[string][]string{
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

	var actualSpecific2 typeSpecific2
	err = cli.CustomQuery(ctx, opaQry, nil, &actualSpecific2)
	if err != nil {
		t.Errorf("CustomQuery(Specific2) FAIL: err=%#v", err)
	}
	t.Logf("actualSpecific2=%#v", actualSpecific2)

	if !reflect.DeepEqual(expectSpecific2, actualSpecific2) {
		t.Errorf("CustomQuery(Specific2) FAIL\nexpectSpecific2=%#v\nactualSpecific2=%#v",
			expectSpecific2, actualSpecific2)
	}

	////////////////////////////////////////////////////////////////

	type typeSpecific3 struct {
		Result  map[string]map[string][]string `json:"result"`
		Warning map[string]string `json:"warning"`
	}
	expectSpecific3 := typeSpecific3{
		Result: map[string]map[string][]string{
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
		Warning: map[string]string{
			"code":    "api_usage_warning",
			"message": "'input' key missing from the request",
		},
	}

	var actualSpecific3 typeSpecific3
	err = cli.CustomQuery(ctx, opaQry, nil, &actualSpecific3)
	if err != nil {
		t.Errorf("CustomQuery(Specific3) FAIL: err=%#v", err)
	}
	t.Logf("actualSpecific3=%#v", actualSpecific3)

	if !reflect.DeepEqual(expectSpecific3, actualSpecific3) {
		t.Errorf("CustomQuery(Specific3) FAIL\nexpectSpecific3=%#v\nactualSpecific3=%#v",
			expectSpecific3, actualSpecific3)
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
