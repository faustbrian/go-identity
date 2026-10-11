//go:build integration

package reference_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	primitive "github.com/faustbrian/go-password"
)

// This is a consumer composition test, not live provider interoperability or
// observed audit integration. No domain store, decision or password work is fake.
func referenceHIBPScreening(t *testing.T, policy risk.Policy) func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
	t.Helper()
	type response struct{ suffix, mode string }
	responses := make(map[string]response)
	for _, mode := range []string{"breached", "malformed", "outage", "redirect", "new"} {
		// Synthetic fixtures only. Production derivation stays in the owned client.
		digest := sha1.Sum([]byte("synthetic-reference-" + mode + "-password"))
		encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
		responses[encoded[:5]] = response{encoded[5:], mode}
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Host != "api.pwnedpasswords.com" || r.URL.RawQuery != "" || r.Header.Get("Add-Padding") != "true" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 || !strings.HasPrefix(r.URL.Path, "/range/") {
			t.Error("HIBP request disclosed more than the padded prefix protocol")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		row, ok := responses[strings.TrimPrefix(r.URL.Path, "/range/")]
		if !ok {
			t.Error("HIBP request did not derive the exact synthetic candidate prefix")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch row.mode {
		case "breached":
			_, _ = fmt.Fprintf(w, "%s:17\r\n", row.suffix)
		case "malformed":
			_, _ = w.Write([]byte("not-a-range-row\n"))
		case "outage":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "redirect":
			w.Header().Set("Location", "https://api.pwnedpasswords.com/disallowed")
			w.WriteHeader(http.StatusFound)
		default:
			// A matching zero-count padding row must not deny a clean candidate.
			_, _ = fmt.Fprintf(w, "%s:0\r\n", row.suffix)
		}
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	httpOwner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := httpOwner.Close(); err != nil {
			t.Error(err)
		}
	})
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-reference/synthetic-test", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1024, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: time.Second, PolicyVersion: "reference-reset-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 1024, DisableCache: true}, httpOwner, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	owner := checker.(*hibp.Client)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := owner.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	provider, err := hibp.NewSignalProvider(owner, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if calls.Load() != 5 {
			t.Error("native screening did not execute each provider case exactly once")
		}
	})
	return func(ctx context.Context, binding risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(binding.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: string(binding.Operation), Action: binding.Operation, TenantID: identity.TenantID(binding.Tenant), ReplayID: command, Purpose: "reset", SubjectScope: "password-reset", PolicyVersion: "reference-reset-v1", Candidate: candidate})
		if err != nil {
			return nil, err
		}
		return []risk.Signal{signal}, nil
	}
}
