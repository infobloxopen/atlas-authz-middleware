package util

import (
	"net/http"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/v2/http_opa/exception"
)

func TestGetBearerFromRequest(t *testing.T) {
	tests := []struct {
		name           string
		request        *http.Request
		expectedBearer string
		expectedError  error
	}{
		{
			name: "Bearer token is present",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer token"},
				},
			},
			expectedBearer: "token",
		},
		{
			name: "Bearer token is not present",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic token"},
				},
			},
			expectedError: exception.ErrAbstrAuthHeaderMissing,
		},
		{
			name: "Bearer token is empty",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{""},
				},
			},
			expectedError: exception.ErrAbstrAuthHeaderMissing,
		},
		{
			name: "Bearer token is present along with other headers",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic basic.token", "Bearer bearer.token"},
				},
			},
			expectedBearer: "bearer.token",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bearer, err := GetBearerFromRequest(test.request)
			if bearer != test.expectedBearer {
				t.Errorf("Expected bearer: %s, but got: %s", test.expectedBearer, bearer)
			}
			if err != test.expectedError {
				t.Errorf("Expected error: %v, but got: %v", test.expectedError, err)
			}
		})
	}
}
