package hibp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk"
)

type cleanupTransportFunc func(*http.Request) (*http.Response, error)

func (f cleanupTransportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type cleanupRangeBody struct {
	io.Reader
	request context.Context
}

// The HTTP primitive cancels its derived request context when Close starts.
// Cleanup may still finish only at the original bounded request deadline.
func (b cleanupRangeBody) Close() error {
	deadline, _ := b.request.Deadline()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	return nil
}

func TestCheckerDeadlineDuringBodyCleanupNeverPublishesOrCachesEvidence(t *testing.T) {
	for _, neutral := range []bool{false, true} {
		t.Run(map[bool]string{false: "checker", true: "neutral-signal"}[neutral], func(t *testing.T) {
			var outbound atomic.Int32
			transport, err := httpclient.New(httpclient.Config{Transport: cleanupTransportFunc(func(request *http.Request) (*http.Response, error) {
				body := io.ReadCloser(io.NopCloser(strings.NewReader("00000000000000000000000000000000000:0\n")))
				if outbound.Add(1) == 1 {
					body = cleanupRangeBody{Reader: body, request: request.Context()}
				}
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header), Request: request}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = transport.Close() })
			wall := &testClock{}
			wall.nanos.Store(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC).UnixNano())
			config := testConfig()
			config.Timeout = time.Second
			checker, err := New(config, transport, wall)
			if err != nil {
				t.Fatal(err)
			}
			client := checker.(*Client)
			t.Cleanup(func() { _ = client.Close(context.Background()) })
			request := requestFor(t, "synthetic-cleanup-deadline")
			request.OperationID = "identity.password.signup"
			request.Action = risk.Action(request.OperationID)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if neutral {
				provider, err := NewSignalProvider(client, adapterPolicy(t, time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				signal, err := provider.Assess(ctx, request)
				if !errors.Is(err, ErrProviderUnavailable) || signal.State != risk.SignalUnavailable || signal.Failure != risk.ProviderUnavailable || !signal.ExpiresAt.IsZero() {
					t.Fatal("expired provider cleanup became usable neutral evidence", err)
				}
			} else {
				result, err := client.Check(ctx, request)
				if !errors.Is(err, ErrProviderUnavailable) || result.Outcome != OutcomeUnavailable || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
					t.Fatal("expired provider cleanup became usable checker evidence", err)
				}
			}
			result, err := client.Check(ctx, request)
			if err != nil || result.Outcome != OutcomeNoMatch || outbound.Load() != 2 {
				t.Fatal("expired provider cleanup populated the private range cache", err)
			}
		})
	}
}
