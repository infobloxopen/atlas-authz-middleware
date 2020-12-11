package grpc_opa_middleware

import (
	"strings"
	"testing"
)

func TestRedactJWT(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	if redacted := redactJWT(token); !strings.HasSuffix(redacted, REDACTED) {

		t.Errorf("got: %s, wanted: %s", redacted, REDACTED)
	}
}

func Test_parseEndpoint(t *testing.T) {
	expected := "TagService.ListRetiredTags"
	if endpoint := parseEndpoint("/service.TagService/ListRetiredTags"); expected != endpoint {
		t.Errorf("got: %s, wanted: %s", endpoint, expected)
	}

}
