package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

func TestAdminRateUsesOneAtomicCanonicalSharedBudget(t *testing.T) {
	f := newFixture(t)
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/organization/create", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a")
	if err != nil || !first.Allowed || f.rate.calls != 1 {
		t.Fatal("canonical atomic admission missing", err)
	}
	previous := f.rate.last
	if len(previous.Requests) != 3 {
		t.Fatal("canonical admin budget was split")
	}
	for i, capacity := range []uint64{30, 100, 60} {
		q := previous.Requests[i]
		if q.Cost != 1 || q.Policy.Capacity() != capacity || q.Policy.Period() != time.Minute || q.Policy.Consistency() != ratelimit.ConsistencyStrong {
			t.Fatal("canonical fixed policy or strong ownership changed")
		}
		if rendered := fmt.Sprintf("%v", q.Key); strings.Contains(rendered, "user-a") || strings.Contains(rendered, "tenant-a") || strings.Contains(rendered, "198.51.100.7") {
			t.Fatal("raw actor/network entered persisted rate key")
		}
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); err != nil || f.rate.calls != 2 {
		t.Fatal("repeat removal used another policy engine", err)
	}
	if f.rate.last.CommandID == previous.CommandID {
		t.Fatal("HTTP repeat attempt became a free cached debit")
	}
	for i, q := range previous.Requests {
		if fmt.Sprint(q.Key) != fmt.Sprint(f.rate.last.Requests[i].Key) || q.Policy.ID() != f.rate.last.Requests[i].Policy.ID() {
			t.Fatal("operation change reset canonical shared buckets")
		}
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), identityhttp.NetworkFacts{}, organization.Create, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 2 {
		t.Fatal("unproven network reached backend")
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.UpdateMember, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 2 {
		t.Fatal("unselected admin operation bypassed finite owner")
	}
	if err := f.c.AdminRate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err == nil || f.rate.calls != 2 {
		t.Fatal("closed owner dispatched again")
	}
}

func TestAdminRateAuditingIsRequiredAndSensitiveConfigurationIsClosed(t *testing.T) {
	f := newFixture(t)
	c := organizationhttp.AdminRateConfig{Shared: f.rate, Namespace: "organization-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second}
	if _, err := organizationhttp.NewAdminRateLimiter(c); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("missing denial owner accepted")
	}
	c.Denied = func(context.Context, organizationhttp.AdminRateEvent) error {
		return errors.New("private audit failure")
	}
	l, err := organizationhttp.NewAdminRateLimiter(c)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f.rate.mode = 1
	resolver, _ := identityhttp.NewNetworkResolver(f.c.Network)
	facts, _ := resolver.Resolve(request(f, "/v1/organization/create", `{}`, true))
	if out, err := l.Admit(t.Context(), facts, organization.Create, "user-a"); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("failed mandatory denial audit was ignored or leaked", err)
	}
	for _, v := range []any{c, l} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit runtime policy export accepted")
		}
		if !strings.Contains(fmt.Sprintf("%#v", v), "redacted") {
			t.Fatal("rate diagnostics traversed borrowed backend")
		}
	}
}
