package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
)

func Test_WithEntitledServices_payload(t *testing.T) {
	var uninitializedStrSlice []string
	withEntitledServicesTests := []struct {
		name                   string
		configEntitledServices interface{}
		expectEntitledServices []string
	}{
		{
			name:                   `dont-call-WithEntitledServices`,
			configEntitledServices: `dont-call-WithEntitledServices`,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices(nil)`,
			configEntitledServices: nil,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices(uninitializedStrSlice)`,
			configEntitledServices: uninitializedStrSlice,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices([])`,
			configEntitledServices: []string{},
			expectEntitledServices: []string{},
		},
		{
			name:                   `WithEntitledServices(["lic"])`,
			configEntitledServices: []string{"lic"},
			expectEntitledServices: []string{"lic"},
		},
		{
			name:                   `WithEntitledServices(["lic","rpz"])`,
			configEntitledServices: []string{"lic", "rpz"},
			expectEntitledServices: []string{"lic", "rpz"},
		},
	}

	testingTCtx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)

	for idx, tstc := range withEntitledServicesTests {
		tcCtx := context.WithValue(testingTCtx, utils_test.TestCaseIndexContextKey, idx)
		tcCtx = context.WithValue(tcCtx, utils_test.TestCaseNameContextKey, tstc.name)

		mockOpaClienter := optionsMockOpaClienter{
			VerifyEntitledServices: true,
			ExpectEntitledServices: tstc.expectEntitledServices,
		}

		auther := NewDefaultAuthorizer("app",
			WithOpaClienter(&mockOpaClienter),
			WithClaimsVerifier(NullClaimsVerifier),
		)

		configEntitledServices, ok := tstc.configEntitledServices.([]string)
		if tstc.configEntitledServices == nil || ok {
			t.Logf("tst#%d: name=%s; calling option WithEntitledServices(%#v)",
				idx, tstc.name, configEntitledServices)
			auther = NewDefaultAuthorizer("app",
				WithOpaClienter(&mockOpaClienter),
				WithClaimsVerifier(NullClaimsVerifier),
				WithEntitledServices(configEntitledServices...),
			)
		}

		auther.AffirmAuthorization(tcCtx, "FakeMethod", nil)
	}
}

func Test_WithExtraInputFields_payload(t *testing.T) {
	var uninitializedExtraInputFields ExtraInputFields
	withExtraInputFieldsTests := []struct {
		name                   string
		configExtraInputFields interface{}
		expectExtraInputFields ExtraInputFields
	}{
		{
			name:                   `dont-call-WithExtraInputFields`,
			configExtraInputFields: `dont-call-WithExtraInputFields`,
			expectExtraInputFields: nil,
		},
		{
			name:                   `WithExtraInputFields(nil)`,
			configExtraInputFields: nil,
			expectExtraInputFields: nil,
		},
		{
			name:                   `WithExtraInputFields(uninitializedExtraInputFields)`,
			configExtraInputFields: uninitializedExtraInputFields,
			expectExtraInputFields: nil,
		},
		{
			name:                   `WithExtraInputFields(ExtraInputFields{})`,
			configExtraInputFields: ExtraInputFields{},
			expectExtraInputFields: nil,
		},
		{
			name:                   `WithExtraInputFields(ExtraInputFields{name:val})`,
			configExtraInputFields: ExtraInputFields{"k1": "v1", "k2": true, "k3": 123},
			expectExtraInputFields: ExtraInputFields{"k1": "v1", "k2": true, "k3": 123},
		},
	}

	testingTCtx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)

	for idx, tstc := range withExtraInputFieldsTests {
		tcCtx := context.WithValue(testingTCtx, utils_test.TestCaseIndexContextKey, idx)
		tcCtx = context.WithValue(tcCtx, utils_test.TestCaseNameContextKey, tstc.name)

		mockOpaClienter := optionsMockOpaClienter{
			VerifyExtraInputFields: true,
			ExpectExtraInputFields: tstc.expectExtraInputFields,
		}

		auther := NewDefaultAuthorizer("app",
			WithOpaClienter(&mockOpaClienter),
			WithClaimsVerifier(NullClaimsVerifier),
		)

		configExtraInputFields, ok := tstc.configExtraInputFields.(ExtraInputFields)
		if tstc.configExtraInputFields == nil || ok {
			t.Logf("tst#%d: name=%s; calling option WithExtraInputFields(%#v)",
				idx, tstc.name, configExtraInputFields)
			auther = NewDefaultAuthorizer("app",
				WithOpaClienter(&mockOpaClienter),
				WithClaimsVerifier(NullClaimsVerifier),
				WithExtraInputFields(configExtraInputFields),
			)
		}

		auther.AffirmAuthorization(tcCtx, "FakeMethod", nil)
	}
}

type optionsMockOpaClienter struct {
	VerifyEntitledServices bool
	ExpectEntitledServices []string

	VerifyExtraInputFields bool
	ExpectExtraInputFields ExtraInputFields
}

func (m optionsMockOpaClienter) String() string {
	return fmt.Sprintf(`optionsMockOpaClienter{VerifyEntitledServices:%v,ExpectEntitledServices:%#v}`,
		m.VerifyEntitledServices, m.ExpectEntitledServices)
}

func (m optionsMockOpaClienter) Address() string {
	return "http://optionsMockOpaClienter:8181"
}

func (m optionsMockOpaClienter) Health() error {
	return nil
}

func (m optionsMockOpaClienter) Query(ctx context.Context, reqData, resp interface{}) error {
	return m.CustomQuery(ctx, "", reqData, resp)
}

func (m optionsMockOpaClienter) CustomQueryStream(ctx context.Context, document string, postReqBody []byte, respRdrFn opa_client.StreamReaderFn) error {
	return nil
}

func (m optionsMockOpaClienter) CustomQueryBytes(ctx context.Context, document string, reqData interface{}) ([]byte, error) {
	return []byte(`{"allow": true}`), nil
}

func (m optionsMockOpaClienter) CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error {
	t, _ := ctx.Value(utils_test.TestingTContextKey).(*testing.T)
	tcIdx, _ := ctx.Value(utils_test.TestCaseIndexContextKey).(int)
	tcName, _ := ctx.Value(utils_test.TestCaseNameContextKey).(string)
	payload, _ := reqData.(Payload)
	if m.VerifyEntitledServices && !reflect.DeepEqual(payload.EntitledServices, m.ExpectEntitledServices) {
		t.Errorf("tst#%d: FAIL: name=%s; not equal: payload.EntitledServices=%#v; m.ExpectEntitledServices=%#v",
			tcIdx, tcName, payload.EntitledServices, m.ExpectEntitledServices)
	}
	if m.VerifyExtraInputFields && !reflect.DeepEqual(payload.ExtraInputFields, m.ExpectExtraInputFields) {
		t.Errorf("tst#%d: FAIL: name=%s; not equal: payload.ExtraInputFields=%#v; m.ExpectExtraInputFields=%#v",
			tcIdx, tcName, payload.ExtraInputFields, m.ExpectExtraInputFields)
	}
	return json.Unmarshal([]byte(`{"allow": true}`), resp)
}
