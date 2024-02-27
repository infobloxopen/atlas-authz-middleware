package utils_test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/infobloxopen/atlas-authz-middleware/v2/pkg/opa_client"
	"github.com/sirupsen/logrus"
)

// MockOpaClienter mocks the opa_client.Clienter interface
type MockOpaClienter struct {
	Loggr        *logrus.Logger
	RegoRespJSON string
}

func (m MockOpaClienter) String() string {
	return fmt.Sprintf(`MockOpaClienter{RegoRespJSON:"%s"}`, m.RegoRespJSON)
}

func (m MockOpaClienter) Address() string {
	return "http://localhost:8181"
}

func (m MockOpaClienter) Health() error {
	return nil
}

func (m MockOpaClienter) Query(ctx context.Context, reqData, resp interface{}) error {
	return m.CustomQuery(ctx, "", reqData, resp)
}

func (m MockOpaClienter) CustomQueryStream(ctx context.Context, document string, postReqBody []byte, respRdrFn opa_client.StreamReaderFn) error {
	return nil
}

func (m MockOpaClienter) CustomQueryBytes(ctx context.Context, document string, reqData interface{}) ([]byte, error) {
	return []byte(m.RegoRespJSON), nil
}

func (m MockOpaClienter) CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error {
	err := json.Unmarshal([]byte(m.RegoRespJSON), resp)
	m.Loggr.Debugf("CustomQuery: resp=%#v", resp)
	return err
}
