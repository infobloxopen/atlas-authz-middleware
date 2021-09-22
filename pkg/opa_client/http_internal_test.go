package opa_client

import (
	"testing"
)

func TestCheckHeaders(t *testing.T) {
	tests := []struct {
		key string
		val string
		eOK bool
	}{
		{
			// NGP-5595
			eOK: false,
			key: "Grpc-Trace-Bin",
			val: "\x00\x00\xe7Z\xa0\xcd\xc4?\xdbT\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		},
		{
			eOK: false,
			key: ":authority",
			val: "",
		},
		{
			eOK: true,
			key: "Authorization",
			val: "Bearer somestring",
		},
	}
	for _, tm := range tests {
		ok := checkHeader("http", tm.key, tm.val)
		if tm.eOK != ok {
			t.Errorf("got: %t wanted: %t", ok, tm.eOK)
		}
	}
}
