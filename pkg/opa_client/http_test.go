package opa_client

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage/inmem"
)

const opaImage = "openpolicyagent/opa:latest"

func TestRestAPI(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	cli := startOpa(ctx, t, done)

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	if err := cli.Health(); err != nil {
		t.Fatal(err)
	}
}

func startOpa(ctx context.Context, t *testing.T, done chan struct{}) Clienter {
	// Retrieve a random port from the OS and pass it to opa
	l, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	addrs := []string{addr}

	bs := []byte{}
	store := inmem.New()
	m, err := plugins.New(bs, "test", store)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}

	opaSvr := server.New().
		WithAddresses(addrs).
		WithStore(store).
		WithManager(m)

	opaSvr, err = opaSvr.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}

	loops, err := opaSvr.Listeners()
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	errc := make(chan error)
	for _, loop := range loops {
		go func(serverLoop func() error) {
			errc <- serverLoop()
		}(loop)
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if err := opaSvr.Shutdown(shutdownCtx); err != nil {
			t.Fatal(err)
		}
		close(done)
	}()

	cli := New("http://" + addr)
	timeout := time.After(3 * time.Second)
	for {
		select {
		case <-timeout:
			t.Fatal("time out starting opa")
		default:
			if err := cli.Health(); err == nil {
				return cli
			}
			t.Logf("opa not ready: %s", err)
			time.Sleep(50 * time.Millisecond)
		}
	}
}

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

func TestConnectionRefused(t *testing.T) {

	cli := New("http://localhost:0001")
	err := cli.Health()
	if err == nil {
		t.Error("unexpected nil err")
	}

	if _, ok := err.(*ErrorV1); !ok {
		t.Errorf("unexpected unstructured error: %#v", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("\ngot:    %#v\nwanted: %#v", err, syscall.ECONNREFUSED)
	}
}
