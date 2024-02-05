// Code generated by mockery v2.40.1. DO NOT EDIT.

package authorizer

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockOpaEvaluator is an autogenerated mock type for the OpaEvaluator type
type MockOpaEvaluator struct {
	mock.Mock
}

type MockOpaEvaluator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockOpaEvaluator) EXPECT() *MockOpaEvaluator_Expecter {
	return &MockOpaEvaluator_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: ctx, decisionDocument, opaReq, opaResp
func (_m *MockOpaEvaluator) Execute(ctx context.Context, decisionDocument string, opaReq interface{}, opaResp interface{}) error {
	ret := _m.Called(ctx, decisionDocument, opaReq, opaResp)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, interface{}, interface{}) error); ok {
		r0 = rf(ctx, decisionDocument, opaReq, opaResp)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockOpaEvaluator_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockOpaEvaluator_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - ctx context.Context
//   - decisionDocument string
//   - opaReq interface{}
//   - opaResp interface{}
func (_e *MockOpaEvaluator_Expecter) Execute(ctx interface{}, decisionDocument interface{}, opaReq interface{}, opaResp interface{}) *MockOpaEvaluator_Execute_Call {
	return &MockOpaEvaluator_Execute_Call{Call: _e.mock.On("Execute", ctx, decisionDocument, opaReq, opaResp)}
}

func (_c *MockOpaEvaluator_Execute_Call) Run(run func(ctx context.Context, decisionDocument string, opaReq interface{}, opaResp interface{})) *MockOpaEvaluator_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(interface{}), args[3].(interface{}))
	})
	return _c
}

func (_c *MockOpaEvaluator_Execute_Call) Return(_a0 error) *MockOpaEvaluator_Execute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockOpaEvaluator_Execute_Call) RunAndReturn(run func(context.Context, string, interface{}, interface{}) error) *MockOpaEvaluator_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockOpaEvaluator creates a new instance of MockOpaEvaluator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockOpaEvaluator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockOpaEvaluator {
	mock := &MockOpaEvaluator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
