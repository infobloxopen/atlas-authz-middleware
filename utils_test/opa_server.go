package utils_test

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"

	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func StartOpa(ctx context.Context, t *testing.T, done chan struct{}) opa_client.Clienter {
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

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if err := opaSvr.Shutdown(shutdownCtx); err != nil {
			t.Logf(err.Error())
			os.Exit(1)
		}
		close(done)
	}()

	cli := opa_client.New("http://" + addr)
	timeout := time.After(3 * time.Second)
	for {
		select {
		case <-timeout:
			t.Fatal("time out starting opa")
		default:
			if err := cli.Health(); err == nil {
				t.Logf("opa started")
				return cli
			}
			t.Logf("opa not ready: %s", err)
			time.Sleep(50 * time.Millisecond)
		}
	}
}
