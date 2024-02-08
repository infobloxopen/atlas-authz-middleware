// Code generated by MockGen. DO NOT EDIT.
// Source: authorizer.go

// Package authorizer is a generated GoMock package.
package authorizer

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockAuthorizer is a mock of Authorizer interface.
type MockAuthorizer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizerMockRecorder
}

// MockAuthorizerMockRecorder is the mock recorder for MockAuthorizer.
type MockAuthorizerMockRecorder struct {
	mock *MockAuthorizer
}

// NewMockAuthorizer creates a new mock instance.
func NewMockAuthorizer(ctrl *gomock.Controller) *MockAuthorizer {
	mock := &MockAuthorizer{ctrl: ctrl}
	mock.recorder = &MockAuthorizerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizer) EXPECT() *MockAuthorizerMockRecorder {
	return m.recorder
}

// AffirmAuthorization mocks base method.
func (m *MockAuthorizer) AffirmAuthorization(ctx context.Context, fullMethod string, eq interface{}) (context.Context, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AffirmAuthorization", ctx, fullMethod, eq)
	ret0, _ := ret[0].(context.Context)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AffirmAuthorization indicates an expected call of AffirmAuthorization.
func (mr *MockAuthorizerMockRecorder) AffirmAuthorization(ctx, fullMethod, eq interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AffirmAuthorization", reflect.TypeOf((*MockAuthorizer)(nil).AffirmAuthorization), ctx, fullMethod, eq)
}

// Evaluate mocks base method.
func (m *MockAuthorizer) Evaluate(ctx context.Context, fullMethod string, req interface{}, opaEvaluator OpaEvaluator) (bool, context.Context, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Evaluate", ctx, fullMethod, req, opaEvaluator)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(context.Context)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Evaluate indicates an expected call of Evaluate.
func (mr *MockAuthorizerMockRecorder) Evaluate(ctx, fullMethod, req, opaEvaluator interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Evaluate", reflect.TypeOf((*MockAuthorizer)(nil).Evaluate), ctx, fullMethod, req, opaEvaluator)
}

// OpaQuery mocks base method.
func (m *MockAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpaQuery", ctx, decisionDocument, opaReq, opaResp)
	ret0, _ := ret[0].(error)
	return ret0
}

// OpaQuery indicates an expected call of OpaQuery.
func (mr *MockAuthorizerMockRecorder) OpaQuery(ctx, decisionDocument, opaReq, opaResp interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpaQuery", reflect.TypeOf((*MockAuthorizer)(nil).OpaQuery), ctx, decisionDocument, opaReq, opaResp)
}
