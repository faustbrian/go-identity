package routerconsumer_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// This fixture runs as a disposable external consumer, not an internal package.
// It imports only base HTTP and the standard library; no reference/optional
// feature implementation or consumer-written domain store is needed.
func TestSelectedRouterPublicComposition(t *testing.T) {
	var server *identityhttp.HTTPServer
	var checks atomic.Int32
	feature, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
		State: func() identityhttp.ServerState {
			if server == nil {
				return identityhttp.ServerNew
			}
			return server.State()
		}, Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
			checks.Add(1)
			return identityhttp.ReadinessSnapshot{Ready: true}, ctx.Err()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	services := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
	ops, err := identityhttp.NewOperationDescriptors(services)
	if err != nil {
		t.Fatal(err)
	}
	policy := identityhttp.TransportPolicy{HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Consumer", Version: "1"}, Network: identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4},
		MaximumForwardedHops: 1, TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, PublicHosts: []string{"login.example"},
	}}
	h, doc, err := identityhttp.NewRouter(policy, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	if checks.Load() != 0 || len(doc.Operations()) != len(ops) {
		t.Fatal("construction invoked readiness or lost metadata")
	}
	var wire struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &wire) != nil || len(wire.Paths) != 2 || wire.Paths["/healthz"]["get"] == nil || wire.Paths["/readyz"]["get"] == nil {
		t.Fatal("wire/handler mismatch")
	}
	if bad, document, err := identityhttp.NewRouter(policy, append(ops, ops[0]), nil); err == nil || bad != nil || len(document.JSON()) != 0 {
		t.Fatal("collision returned partial construction")
	}
	r := httptest.NewRequest("GET", "/readyz", nil)
	r.Host = "login.example"
	r.RemoteAddr = "198.51.100.1:1234"
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || checks.Load() != 0 {
		t.Fatal("ready before startup")
	}
	server, err = identityhttp.NewHTTPServer(identityhttp.ServerConfig{Address: "127.0.0.1:0", ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, HandlerTimeout: time.Second, ShutdownDrain: time.Second, MaximumHeaderBytes: 4096}, h)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("unjoined server")
		}
	})
	select {
	case <-server.Started():
	case <-ctx.Done():
		t.Fatal("server did not start")
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"GET", "/readyz", 200}, {"GET", "/healthz", 200}, {"GET", "/v1/healthz", 404}, {"HEAD", "/healthz", 405}, {"OPTIONS", "/readyz", 405}} {
		req, err := http.NewRequestWithContext(ctx, tc.method, "http://"+listener.Addr().String()+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "login.example"
		req.Header.Set("Forwarded", `for=198.51.100.1;host=login.example;proto=https`)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 2048))
		res.Body.Close()
		if readErr != nil || res.StatusCode != tc.want || res.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "login.example") {
			t.Fatal("network composition mismatch", tc.path, res.StatusCode)
		}
	}
	if checks.Load() != 1 {
		t.Fatal("unexpected composed readiness calls")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || checks.Load() != 1 {
		t.Fatal("ready after drain")
	}
}
