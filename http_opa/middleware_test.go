package httpopa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
	"gotest.tools/v3/assert"
)

// TestAuthzMiddleware is a unit test function that tests the behavior of the AuthzMiddleware function.
// It uses a table-driven approach to test different scenarios of authorized and unauthorized requests.
// The function takes a testing.T parameter for test assertions.
// The test cases include authorized and unauthorized requests with different application names and authorizer modifications.
// For each test case, it creates a new mock authorizer, modifies it based on the test case, and then runs the AuthzMiddleware function with the modified authorizer.
// Finally, it asserts the expected authorization result based on the test case.
func TestAuthzMiddleware(t *testing.T) {
	testCases := []struct {
		name             string
		application      string
		opts             []Option
		expectAuth       bool
		modifyAuthorizer func(*authorizer.MockAuthorizer)
	}{
		{
			name:        "Authorized request",
			application: "testApp",
			modifyAuthorizer: func(ma *authorizer.MockAuthorizer) {
				ma.EXPECT().Evaluate(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, context.Background(), nil)
			},
			expectAuth: true,
		},
		{
			name:        "Unauthorized request",
			application: "testApp",
			modifyAuthorizer: func(ma *authorizer.MockAuthorizer) {
				ma.EXPECT().Evaluate(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, context.Background(), exception.ErrForbidden)
			},
			expectAuth: false,
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ma := authorizer.NewMockAuthorizer(ctrl)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			})

			tc.modifyAuthorizer(ma)

			tc.opts = append(tc.opts, WithAuthorizer(ma))

			request := httptest.NewRequest(http.MethodGet, "/", nil)

			middleware := NewServerAuthzMiddleware(tc.application, tc.opts...)
			rr := httptest.NewRecorder()

			middleware(handler).ServeHTTP(rr, request)

			assert.Equal(t, tc.expectAuth, rr.Code == http.StatusOK, "Expected authorized request")

		})
	}
}
