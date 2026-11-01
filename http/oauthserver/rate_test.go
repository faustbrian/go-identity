package oauthserverhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// The real primitive owns counting. Only the storage consistency/outage seam
// is substituted here; actual PostgreSQL rate ownership is a composed test.
type rateBackend struct {
	*memory.Store
	err error
}

func (*rateBackend) Name() string { return "oauth-wire-rate-test" }
func (b *rateBackend) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	if b.err != nil {
		return ratelimit.Decision{}, b.err
	}
	if r.Policy.Consistency() != ratelimit.ConsistencyStrong {
		return ratelimit.Decision{}, ratelimit.ErrInvalidPolicy
	}
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return b.Store.AdmitStrict(ctx, r)
}

func rateFixture(t *testing.T) (*protocolRate, *rateBackend) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 4096, Shards: 1, RejectOnCapacity: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	backend := &rateBackend{Store: store}
	l, err := newProtocolRate(RateConfig{Shared: backend, Namespace: "oauth-test", Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second}, "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	return l, backend
}

func rateFacts(t *testing.T, ip, tenant string) identityhttp.NetworkFacts {
	t.Helper()
	c := identityhttp.NetworkConfig{MaximumForwardedHops: 8, Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 16, MaximumDepth: 2}}
	if tenant == "" {
		c.PublicHosts = []string{"issuer.example"}
	} else {
		c.TenantHosts = []identityhttp.TenantHost{{Host: "issuer.example", TenantID: identity.TenantID(tenant)}}
	}
	n, err := identityhttp.NewNetworkResolver(c)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/oauth2/token", nil)
	r.Host, r.TLS = "issuer.example", &tls.ConnectionState{}
	r.RemoteAddr = ip + ":1234"
	f, err := n.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestProtocolRateTokenIPAndAuthenticatedClientBudgets(t *testing.T) {
	l, _ := rateFixture(t)
	f := rateFacts(t, "198.51.100.1", "")
	for i := range 121 {
		retry, err := l.admitIP(context.Background(), f, "token")
		if i < 120 && err != nil || i == 120 && (!errors.Is(err, identityhttp.ErrRateLimited) || retry < time.Second) {
			t.Fatal("token IP budget", i, err)
		}
	}
	l, _ = rateFixture(t)
	for i := range 61 {
		f = rateFacts(t, fmt.Sprintf("198.51.100.%d", i+1), "")
		retry, err := l.admitClient(context.Background(), f, "token", "authenticated-client")
		if i < 60 && err != nil || i == 60 && (!errors.Is(err, identityhttp.ErrRateLimited) || retry < time.Second) {
			t.Fatal("token client budget", i, err)
		}
	}
	if _, err := l.admitClient(context.Background(), f, "token", "other-authenticated-client"); err != nil {
		t.Fatal("one client's budget exhausted another", err)
	}
}

func TestProtocolRateIntrospectionAndRevocationShareBudgets(t *testing.T) {
	l, _ := rateFixture(t)
	f := rateFacts(t, "198.51.100.2", "")
	for i := range 241 {
		action := []string{"introspect", "revoke"}[i%2]
		_, err := l.admitIP(context.Background(), f, action)
		if i < 240 && err != nil || i == 240 && !errors.Is(err, identityhttp.ErrRateLimited) {
			t.Fatal("shared protocol IP budget", i, err)
		}
	}
	l, _ = rateFixture(t)
	for i := range 121 {
		_, err := l.admitClient(context.Background(), f, []string{"introspect", "revoke"}[i%2], "authenticated-client")
		if i < 120 && err != nil || i == 120 && !errors.Is(err, identityhttp.ErrRateLimited) {
			t.Fatal("shared protocol client budget", i, err)
		}
	}
	if _, err := l.admitClient(context.Background(), f, "token", "authenticated-client"); err != nil {
		t.Fatal("protocol admission consumed token policy", err)
	}
}

func TestProtocolRateTenantScopeAndFailClosed(t *testing.T) {
	l, backend := rateFixture(t)
	f := rateFacts(t, "198.51.100.3", "tenant-a")
	for i := range 601 {
		_, err := l.admitClient(context.Background(), f, "introspect", fmt.Sprintf("client-%d", i))
		if i < 600 && err != nil || i == 600 && !errors.Is(err, identityhttp.ErrRateLimited) {
			t.Fatal("issuer tenant budget", i, err)
		}
	}
	if _, err := l.admitClient(context.Background(), rateFacts(t, "198.51.100.3", "tenant-b"), "introspect", "client-new"); err != nil {
		t.Fatal("tenant budget crossed tenant scope", err)
	}
	for _, mode := range []error{ratelimit.ErrUnavailable, ratelimit.UnknownOutcome(nil)} {
		backend.err = mode
		if _, err := l.admitIP(context.Background(), f, "token"); !errors.Is(err, identityhttp.ErrRateUnavailable) {
			t.Fatal("unavailable rate authority did not fail closed", err)
		}
	}
	backend.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.admitIP(ctx, f, "token"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled admission lost context", err)
	}
	if _, err := l.admitIP(context.Background(), identityhttp.NetworkFacts{}, "token"); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("untrusted network facts admitted", err)
	}
	if _, err := l.admitIP(context.Background(), f, "unknown"); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("unknown protocol policy admitted", err)
	}
}
