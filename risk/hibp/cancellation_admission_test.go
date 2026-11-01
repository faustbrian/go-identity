package hibp

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
)

func TestCheckerCancellationDrainingWorkRetainsAdmissionAndShutdownOwnership(t *testing.T) {
	started, cancelling, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	transport, err := httpclient.New(httpclient.Config{Transport: cleanupTransportFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		<-request.Context().Done()
		close(cancelling)
		// Model finite transport cleanup after cancellation, without allowing a
		// cancelled caller to retain the synchronous Check invocation.
		<-release
		return nil, request.Context().Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	wall := &testClock{}
	wall.nanos.Store(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	config := testConfig()
	config.MaxWaiters = 1
	checker, err := New(config, transport, wall)
	if err != nil {
		t.Fatal(err)
	}
	client := checker.(*Client)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	releaseTransport := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseTransport)
	request := requestFor(t, "synthetic-cancellation-drain")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := launch(client, ctx, request)
	receive(t, started)
	cancel()
	if reply := receive(t, first); !errors.Is(reply.err, context.Canceled) || reply.result.BreachCount != 0 || !reply.result.ProviderValidUntil.IsZero() {
		t.Fatal("cancelled caller retained usable evidence or waited for transport cleanup", reply.err)
	}
	receive(t, cancelling)
	for _, next := range []CheckRequest{request, requestFor(t, "synthetic-other-cancellation-drain")} {
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		result, err := client.Check(bounded, next)
		stop()
		if !errors.Is(err, ErrOverloaded) || result.Outcome != OutcomeUnavailable || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
			t.Fatal("abandoned provider work escaped admission or absorbed another waiter", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("draining transport was bypassed by another outbound request")
	}
	closed, stop := context.WithCancel(context.Background())
	stop()
	if err := client.Close(closed); !errors.Is(err, context.Canceled) {
		t.Fatal("shutdown claimed to drain outstanding transport cleanup", err)
	}
	if _, err := client.Check(context.Background(), request); !errors.Is(err, ErrClosed) {
		t.Fatal("interrupted shutdown reopened admission", err)
	}
	releaseTransport()
	if err := client.Close(context.Background()); err != nil {
		t.Fatal("repeated shutdown did not drain released transport cleanup", err)
	}
}
