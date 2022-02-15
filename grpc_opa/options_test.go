package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
)

func Test_WithEntitledServices_payload(t *testing.T) {
	var uninitializedStrSlice []string
	withEntitledServicesTests := []struct {
		name                   string
		inputEntitledServices  interface{}
		expectEntitledServices []string
	}{
		{
			name:                   `dont-call-WithEntitledServices`,
			inputEntitledServices:  `dont-call-WithEntitledServices`,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices(nil)`,
			inputEntitledServices:  nil,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices(uninitializedStrSlice)`,
			inputEntitledServices:  uninitializedStrSlice,
			expectEntitledServices: nil,
		},
		{
			name:                   `WithEntitledServices([])`,
			inputEntitledServices:  []string{},
			expectEntitledServices: []string{},
		},
		{
			name:                   `WithEntitledServices(["lic"])`,
			inputEntitledServices:  []string{"lic"},
			expectEntitledServices: []string{"lic"},
		},
		{
			name:                   `WithEntitledServices(["lic","rpz"])`,
			inputEntitledServices:  []string{"lic", "rpz"},
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

		inputEntitledServices, ok := tstc.inputEntitledServices.([]string)
		if tstc.inputEntitledServices == nil || ok {
			t.Logf("tst#%d: name=%s; calling option WithEntitledServices(%#v)",
				idx, tstc.name, inputEntitledServices)
			auther = NewDefaultAuthorizer("app",
				WithOpaClienter(&mockOpaClienter),
				WithClaimsVerifier(NullClaimsVerifier),
				WithEntitledServices(inputEntitledServices...),
			)
		}

		auther.AffirmAuthorization(tcCtx, "FakeMethod", nil)
	}
}

type optionsMockOpaClienter struct {
	VerifyEntitledServices bool
	ExpectEntitledServices []string
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

func (m optionsMockOpaClienter) Query(ctx context.Context, data interface{}, resp interface{}) error {
	return m.CustomQuery(ctx, "", data, resp)
}

func (m optionsMockOpaClienter) CustomQueryRaw(ctx context.Context, document string, data []byte) ([]byte, error) {
	return []byte(`{"allow": true}`), nil
}

func (m optionsMockOpaClienter) CustomQuery(ctx context.Context, document string, data interface{}, resp interface{}) error {
	t, _ := ctx.Value(utils_test.TestingTContextKey).(*testing.T)
	tcIdx, _ := ctx.Value(utils_test.TestCaseIndexContextKey).(int)
	tcName, _ := ctx.Value(utils_test.TestCaseNameContextKey).(string)
	payload, _ := data.(Payload)
	if m.VerifyEntitledServices && !reflect.DeepEqual(payload.EntitledServices, m.ExpectEntitledServices) {
		t.Errorf("tst#%d: FAIL: name=%s; not equal: payload.EntitledServices=%#v; m.ExpectEntitledServices=%#v",
			tcIdx, tcName, payload.EntitledServices, m.ExpectEntitledServices)
	}
	return json.Unmarshal([]byte(`{"allow": true}`), resp)
}
