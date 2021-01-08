package grpc_opa_middleware

import (
	"context"
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

func Test_addObligations(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "allow", false)
	resp := make(OPAResponse)
	resp["allow"] = true

	// without obligations
	resCtx := addObligations(ctx, resp)
	if v, ok := resCtx.Value(obKey).([]string); ok {
		t.Fatalf("received obligations data: %v .. was expected to be <nil>", v)
	}

	// with obligations
	resp["obligations"] = []string{`ctx.metric == "dhcp"`}
	resCtx = addObligations(ctx, resp)
	if s, ok := resCtx.Value(obKey).([]string); !ok {
		t.Fatal("obligations data missing")
	} else if strings.Compare(`ctx.metric == "dhcp"`, s[0]) != 0 {
		t.Fatal("obligations data mismatch,received:", s[0])
	}
}
