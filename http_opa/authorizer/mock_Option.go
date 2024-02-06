// Code generated by mockery v2.40.1. DO NOT EDIT.

package authorizer

import mock "github.com/stretchr/testify/mock"

// MockOption is an autogenerated mock type for the Option type
type MockOption struct {
	mock.Mock
}

type MockOption_Expecter struct {
	mock *mock.Mock
}

func (_m *MockOption) EXPECT() *MockOption_Expecter {
	return &MockOption_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: c
func (_m *MockOption) Execute(c *Config) {
	_m.Called(c)
}

// MockOption_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockOption_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - c *Config
func (_e *MockOption_Expecter) Execute(c interface{}) *MockOption_Execute_Call {
	return &MockOption_Execute_Call{Call: _e.mock.On("Execute", c)}
}

func (_c *MockOption_Execute_Call) Run(run func(c *Config)) *MockOption_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*Config))
	})
	return _c
}

func (_c *MockOption_Execute_Call) Return() *MockOption_Execute_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockOption_Execute_Call) RunAndReturn(run func(*Config)) *MockOption_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockOption creates a new instance of MockOption. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockOption(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockOption {
	mock := &MockOption{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}