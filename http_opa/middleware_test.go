package httpopa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/http_opa/authorizer"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/exception"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthzMiddleware(t *testing.T) {
	testCases := []struct {
		name             string
		application      string
		opts             []authorizer.Option
		expectAuth       bool
		modifyAuthorizer func(*authorizer.MockAuthorizer)
	}{
		{
			name:        "Authorized request",
			application: "testApp",
			modifyAuthorizer: func(ma *authorizer.MockAuthorizer) {
				ma.On("Evaluate", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(true, context.Background(), nil)
			},
			expectAuth: true,
		},
		{
			name:        "Unauthorized request",
			application: "testApp",
			modifyAuthorizer: func(ma *authorizer.MockAuthorizer) {
				ma.On("Evaluate", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(false, context.Background(), exception.ErrForbidden)
			},
			expectAuth: false,
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			})

			ma := &authorizer.MockAuthorizer{}
			tc.modifyAuthorizer(ma)

			tc.opts = append(tc.opts, authorizer.WithAuthorizer(ma))

			request := httptest.NewRequest(http.MethodGet, "/", nil)

			middleware := NewServerAuthzMiddleware(tc.application, tc.opts...)
			rr := httptest.NewRecorder()

			middleware(handler).ServeHTTP(rr, request)
			assert.Equal(t, tc.expectAuth, rr.Code == http.StatusOK, "Expected authorized request")
		})
	}
}
