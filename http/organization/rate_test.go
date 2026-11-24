package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

type directoryRateAdmitter interface {
	AdmitDirectorySync(context.Context, identityhttp.NetworkFacts, string, identity.UserID) (time.Duration, error)
}

// budgetBackend fixes time for a bounded atomic-budget contract test. Production
// admission still requires the caller's native shared atomic backend.
type budgetBackend struct {
	ratelimit.StrictBackend
	used map[string]uint64
}

func (*budgetBackend) Name() string { return "test-only-atomic-budget" }
func (b *budgetBackend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if err := ctx.Err(); err != nil {
		return ratelimit.AtomicBatchDecision{}, err
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, q := range r.Requests {
		remaining := q.Policy.Capacity() - b.used[q.Policy.ID()+"\x00"+q.Key.String()]
		d := ratelimit.Decision{Allowed: remaining >= q.Cost, Remaining: remaining, Limit: q.Policy.Capacity(), Reset: q.Now.Add(q.Policy.Period()), Reason: ratelimit.ReasonAllowed}
		if !d.Allowed {
			out.Allowed = false
			d.Reason, d.RetryAfter = ratelimit.ReasonLimited, 1500*time.Millisecond
		} else {
			d.Remaining -= q.Cost
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

func TestDirectorySyncSharesActualAdministrativeBudgetAndAuditsExactOperation(t *testing.T) {
	for _, operationID := range []string{"identity.sso.directory-sync-start", "identity.sso.directory-sync-cancel"} {
		t.Run(operationID, func(t *testing.T) {
			f := newFixture(t)
			var events []organizationhttp.AdminRateEvent
			limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: &budgetBackend{used: make(map[string]uint64)}, Namespace: "organization-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second, Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("directory denial audit lacks its admission deadline")
				}
				events = append(events, event)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { limiter.Close() })
			directory, ok := any(limiter).(directoryRateAdmitter)
			if !ok {
				t.Fatal("shared administrative owner cannot admit directory sync")
			}
			resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := resolver.Resolve(request(f, "/v1/organization/create", `{}`, true))
			if err != nil {
				t.Fatal(err)
			}
			for range 29 {
				if out, err := limiter.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
					t.Fatal("administrative budget exhausted before its actor capacity", err)
				}
			}
			if retry, err := directory.AdmitDirectorySync(t.Context(), facts, operationID, "user-a"); err != nil || retry != 0 {
				t.Fatal("directory admission did not consume the final shared actor token", retry, err)
			}
			if retry, err := directory.AdmitDirectorySync(t.Context(), facts, operationID, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || retry != 2*time.Second {
				t.Fatal("directory admission reset or bypassed the exhausted administrative budget", retry, err)
			}
			if len(events) != 1 || string(events[0].Operation) != operationID || events[0].Reason != "limited" {
				t.Fatal("directory denial did not audit its exact operation", events)
			}
			if out, err := limiter.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
				t.Fatal("directory attempt did not debit the organization budget", err)
			}
		})
	}
}

func TestDirectorySyncAdmissionIsFiniteAndFailClosed(t *testing.T) {
	f := newFixture(t)
	directory, ok := any(f.c.AdminRate).(directoryRateAdmitter)
	if !ok {
		t.Fatal("shared administrative owner cannot admit directory sync")
	}
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/organization/create", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{"", string(organization.Create), "identity.sso.directory-sync-status", "identity.sso.directory-sync-start-extra"} {
		if retry, err := directory.AdmitDirectorySync(t.Context(), facts, operationID, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != 0 {
			t.Fatal("unselected operation reached administrative backend", retry, err)
		}
	}
	for _, mode := range []int{2, 3, 4} {
		f.rate.mode = mode
		if retry, err := directory.AdmitDirectorySync(t.Context(), facts, "identity.sso.directory-sync-start", "user-a"); !errors.Is(err, identityhttp.ErrRateUnavailable) || retry != 0 {
			t.Fatal("unavailable directory admission became success", retry, err)
		}
	}
	if f.denials.Load() != 3 {
		t.Fatal("unavailable directory admissions escaped mandatory denial auditing")
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Operation("identity.sso.directory-sync-start"), "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 3 {
		t.Fatal("organization admission was broadened to directory operations")
	}
}

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
	for _, op := range []organization.Operation{organization.Update, organization.UpdateMember, organization.Archive, organization.Restore, organization.CreateTeam, organization.UpdateTeam, organization.DeleteTeam, organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		if out, err := f.c.AdminRate.Admit(t.Context(), facts, op, "user-a"); err != nil || !out.Allowed {
			t.Fatal("selected update lost shared administrative admission", err)
		}
		for i, q := range previous.Requests {
			if fmt.Sprint(q.Key) != fmt.Sprint(f.rate.last.Requests[i].Key) || q.Policy.ID() != f.rate.last.Requests[i].Policy.ID() {
				t.Fatal("update operation reset shared administrative buckets")
			}
		}
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.GetTeam, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 12 {
		t.Fatal("unselected admin operation bypassed finite owner")
	}
	if err := f.c.AdminRate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err == nil || f.rate.calls != 12 {
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
