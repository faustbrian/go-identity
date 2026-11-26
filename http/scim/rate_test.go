package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	scim "github.com/faustbrian/go-scim"
)

// protocolRateBackend records the strict atomic boundary and models fixed-clock
// capacity only. It is not a production token-bucket implementation.
type protocolRateBackend struct {
	ratelimit.StrictBackend
	calls int
	last  ratelimit.AtomicBatchRequest
	used  map[string]uint64
	run   func(context.Context, ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error)
}

func (*protocolRateBackend) Name() string { return "scim-rate-fixture" }
func (b *protocolRateBackend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	b.calls++
	b.last = r
	if b.run != nil {
		return b.run(ctx, r)
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, q := range r.Requests {
		remaining := q.Policy.Capacity() - b.used[q.Policy.ID()+"\x00"+q.Key.String()]
		d := ratelimit.Decision{Allowed: remaining >= q.Cost, Limit: q.Policy.Capacity(), Remaining: remaining, Reset: q.Now.Add(q.Policy.Period()), Reason: ratelimit.ReasonAllowed}
		if d.Allowed {
			d.Remaining -= q.Cost
		} else {
			out.Allowed = false
			d.Reason, d.RetryAfter = ratelimit.ReasonLimited, 1500*time.Millisecond
		}
		out.Decisions[i] = d
	}
	if !out.Allowed {
		for i, q := range r.Requests {
			if out.Decisions[i].Allowed {
				out.Decisions[i].Allowed = false
				out.Decisions[i].Reason = ratelimit.ReasonAtomicRejected
				out.Decisions[i].Remaining += q.Cost
			}
		}
		return out, ratelimit.ErrRejected
	}
	for _, q := range r.Requests {
		b.used[q.Policy.ID()+"\x00"+q.Key.String()] += q.Cost
	}
	return out, nil
}

func protocolRateFixture(t *testing.T) (*protocolRate, *protocolRateBackend, ProtocolRateConfig) {
	t.Helper()
	b := &protocolRateBackend{used: make(map[string]uint64)}
	c := ProtocolRateConfig{Shared: b, Namespace: "scim-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second}
	l, err := newProtocolRate(c)
	if err != nil {
		t.Fatal(err)
	}
	return l, b, c
}

func TestProtocolRateAtomicCanonicalBucketsAndFreshAttempts(t *testing.T) {
	l, b, _ := protocolRateFixture(t)
	client := scim.ProtocolClient{ID: "client-a", TenantID: "tenant-a"}
	ip := netip.MustParseAddr("198.51.100.7")
	if err := l.admit(t.Context(), client, ip); err != nil || b.calls != 1 {
		t.Fatal("complete atomic admission failed", err)
	}
	first := b.last
	if len(first.Requests) != 3 || first.CommandID == "" {
		t.Fatal("required dimensions were split or correlation missing")
	}
	for i, capacity := range []uint64{120, 240, 600} {
		q := first.Requests[i]
		if q.Cost != 1 || q.Policy.Capacity() != capacity || q.Policy.Period() != time.Minute || q.Policy.Consistency() != ratelimit.ConsistencyStrong || q.Policy.FailureMode() != ratelimit.FailClosed {
			t.Fatal("canonical strong fail-closed rate.protocol policy changed")
		}
		for _, secret := range []string{"client-a", "tenant-a", ip.String()} {
			if strings.Contains(q.Key.String(), secret) {
				t.Fatal("raw authenticated or network dimension entered key")
			}
		}
	}
	if err := l.admit(t.Context(), client, ip); err != nil || b.last.CommandID == first.CommandID {
		t.Fatal("outer retry reused cached debit correlation", err)
	}
	for _, tc := range []struct {
		name    string
		client  scim.ProtocolClient
		ip      netip.Addr
		changed [3]bool
	}{
		{"same", client, ip, [3]bool{}},
		{"mapped-v4", client, netip.MustParseAddr("::ffff:198.51.100.7"), [3]bool{}},
		{"client", scim.ProtocolClient{ID: "client-b", TenantID: "tenant-a"}, ip, [3]bool{true, false, false}},
		{"tenant", scim.ProtocolClient{ID: "client-a", TenantID: "tenant-b"}, ip, [3]bool{true, false, true}},
		{"ip", client, netip.MustParseAddr("198.51.100.8"), [3]bool{false, true, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := l.admit(t.Context(), tc.client, tc.ip); err != nil {
				t.Fatal(err)
			}
			for i, q := range b.last.Requests {
				if (q.Key.String() != first.Requests[i].Key.String()) != tc.changed[i] || q.Policy.ID() != first.Requests[i].Policy.ID() {
					t.Fatal("dimension scope changed an unrelated bucket", i)
				}
			}
		})
	}
	if err := l.admit(t.Context(), client, netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	v6Key := b.last.Requests[1].Key.String()
	if err := l.admit(t.Context(), client, netip.MustParseAddr("2001:db8::2")); err != nil || b.last.Requests[1].Key.String() == v6Key {
		t.Fatal("full IPv6 addresses were subnet-aggregated", err)
	}
}

func TestProtocolRateRejectedBatchDoesNotDebitOtherDimensions(t *testing.T) {
	l, b, _ := protocolRateFixture(t)
	client := scim.ProtocolClient{ID: "client-a", TenantID: "tenant-a"}
	for range 120 {
		if err := l.admit(t.Context(), client, netip.MustParseAddr("198.51.100.7")); err != nil {
			t.Fatal(err)
		}
	}
	for range 601 {
		err := l.admit(t.Context(), client, netip.MustParseAddr("198.51.100.8"))
		if err == nil || err.StatusCode() != 429 || err.RetryAfterSeconds() != 2 {
			t.Fatal("exhausted client did not reject complete batch", err)
		}
	}
	client.ID = "client-b"
	if err := l.admit(t.Context(), client, netip.MustParseAddr("198.51.100.8")); err != nil || b.calls != 722 {
		t.Fatal("rejected attempts partially debited IP or tenant", err)
	}
}

func TestProtocolRateLongestKnownRetryIsCeiledAndClamped(t *testing.T) {
	for _, tc := range []struct {
		name  string
		waits [3]time.Duration
		want  uint32
	}{
		{"subsecond", [3]time.Duration{time.Nanosecond, 2 * time.Nanosecond, time.Nanosecond}, 1},
		{"longest", [3]time.Duration{1500 * time.Millisecond, 2200 * time.Millisecond, time.Second}, 3},
		{"clamped", [3]time.Duration{time.Second, time.Hour + time.Nanosecond, time.Second}, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, b, _ := protocolRateFixture(t)
			b.run = func(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded backend call")
				}
				out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID}
				for i, q := range r.Requests {
					out.Decisions = append(out.Decisions, ratelimit.Decision{Limit: q.Policy.Capacity(), Reset: q.Now.Add(time.Minute), Reason: ratelimit.ReasonLimited, RetryAfter: tc.waits[i]})
				}
				return out, ratelimit.ErrRejected
			}
			err := l.admit(t.Context(), scim.ProtocolClient{ID: "client-a", TenantID: "tenant-a"}, netip.MustParseAddr("198.51.100.7"))
			if err == nil || err.StatusCode() != 429 || err.SCIMType() != "" || err.RetryAfterSeconds() != tc.want {
				t.Fatal("incorrect known quota result", err)
			}
		})
	}
}

func TestProtocolRateUnavailableOutcomesAreRedactedAndNeverRetried(t *testing.T) {
	for _, mode := range []string{"outage", "unknown", "raw-error", "panic", "partial", "invalid-limit", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			l, b, _ := protocolRateFixture(t)
			b.run = func(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
				switch mode {
				case "outage":
					return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
				case "unknown":
					return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
				case "raw-error":
					return ratelimit.AtomicBatchDecision{}, errors.New("private-backend-detail")
				case "panic":
					panic("private-backend-detail")
				case "partial":
					return ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}, nil
				case "timeout":
					<-ctx.Done()
					return ratelimit.AtomicBatchDecision{}, ratelimit.DeadlineOutcome()
				default:
					return ratelimit.AtomicBatchDecision{CommandID: r.CommandID}, ratelimit.ErrRejected
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			client := scim.ProtocolClient{ID: "client-a", TenantID: "tenant-a"}
			ip := netip.MustParseAddr("198.51.100.7")
			err := l.admit(ctx, client, ip)
			if err == nil || err.StatusCode() != 503 || err.RetryAfterSeconds() != 0 || b.calls != 1 {
				t.Fatal("unavailable atomic outcome admitted, hinted or retried", err)
			}
			body, marshalErr := json.Marshal(err)
			if marshalErr != nil || strings.Contains(string(body), "private") || strings.Contains(string(body), "client-a") || strings.Contains(string(body), "tenant-a") || strings.Contains(string(body), ip.String()) {
				t.Fatal("unavailable response disclosed private detail")
			}
			if mode == "unknown" {
				first := b.last.CommandID
				if next := l.admit(t.Context(), client, ip); next == nil || next.StatusCode() != 503 || b.calls != 2 || b.last.CommandID == first {
					t.Fatal("outer attempt reused ambiguous correlation", next)
				}
			}
		})
	}
}

func TestProtocolRateInvalidDimensionsDoNotReachStore(t *testing.T) {
	l, b, _ := protocolRateFixture(t)
	valid := scim.ProtocolClient{ID: "client-a", TenantID: "tenant-a"}
	for _, client := range []scim.ProtocolClient{{}, {ID: "client-a"}, {TenantID: "tenant-a"}, {ID: "client\nprivate", TenantID: "tenant-a"}, {ID: "client-a", TenantID: "tenant\x00a"}} {
		if err := l.admit(t.Context(), client, netip.MustParseAddr("198.51.100.7")); err == nil || err.StatusCode() != 503 {
			t.Fatal("invalid required client dimension admitted", err)
		}
	}
	for _, raw := range []string{"", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1%en0"} {
		addr, _ := netip.ParseAddr(raw)
		if err := l.admit(t.Context(), valid, addr); err == nil || err.StatusCode() != 503 {
			t.Fatal("unusable address admitted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := l.admit(ctx, valid, netip.MustParseAddr("198.51.100.7")); err == nil || err.StatusCode() != 503 {
		t.Fatal("canceled attempt admitted", err)
	}
	if err := l.admit(nil, valid, netip.MustParseAddr("198.51.100.7")); err == nil || err.StatusCode() != 503 {
		t.Fatal("nil context admitted", err)
	}
	if b.calls != 0 {
		t.Fatal("invalid custody reached backend")
	}
}

func TestProtocolRateConfigurationIsValidatedAndRedacted(t *testing.T) {
	l, _, c := protocolRateFixture(t)
	for _, mutate := range []func(*ProtocolRateConfig){
		func(c *ProtocolRateConfig) { c.Shared = nil },
		func(c *ProtocolRateConfig) { c.Shared = (*protocolRateBackend)(nil) },
		func(c *ProtocolRateConfig) { c.Namespace = "" },
		func(c *ProtocolRateConfig) { c.Key = [32]byte{} },
		func(c *ProtocolRateConfig) { c.Now = nil },
		func(c *ProtocolRateConfig) { c.MaximumDuration = 0 },
		func(c *ProtocolRateConfig) { c.MaximumDuration = 2*time.Second + time.Nanosecond },
	} {
		bad := c
		mutate(&bad)
		if _, err := newProtocolRate(bad); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid rate configuration accepted", err)
		}
	}
	for _, value := range []any{c, l} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("runtime custody implicitly serialized")
		}
		if text, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("text serialization not explicitly closed")
		} else if _, err := text.MarshalText(); err == nil {
			t.Fatal("runtime text custody exported")
		}
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("runtime diagnostic traversed backend or key")
		}
	}
}
