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

type scimCreateRateAdmitter interface {
	AdmitSCIMConnectionCreate(context.Context, identityhttp.NetworkFacts, identity.UserID) (organizationhttp.AdminRateResult, error)
}

type impersonationDenyRateAdmitter interface {
	AdmitImpersonationDeny(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error)
}

func TestUserStatusSharesAdministrativeBudgetAndExactDenialAudit(t *testing.T) {
	for _, operationID := range []string{"identity.admin.user-ban", "identity.admin.user-unban"} {
		t.Run(operationID, func(t *testing.T) {
			f := newFixture(t)
			var events []organizationhttp.AdminRateEvent
			limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
				Shared: &budgetBackend{used: make(map[string]uint64)}, Namespace: "organization-test", Key: [32]byte{1},
				Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
				Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("user-status denial audit lacks its admission deadline")
					}
					events = append(events, event)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { limiter.Close() })
			resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := resolver.Resolve(request(f, "/v1/admin/user-ban", `{}`, true))
			if err != nil {
				t.Fatal(err)
			}
			for range 29 {
				if out, err := limiter.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
					t.Fatal("organization budget exhausted before actor capacity", err)
				}
			}
			if retry, err := limiter.AdmitUserStatus(t.Context(), facts, operationID, "user-a"); err != nil || retry != 0 || len(events) != 0 {
				t.Fatal("user-status admission did not consume final shared actor token", retry, err)
			}
			if retry, err := limiter.AdmitUserStatus(t.Context(), facts, operationID, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || retry != 2*time.Second {
				t.Fatal("user-status admission bypassed exhausted shared budget", retry, err)
			}
			if len(events) != 1 || string(events[0].Operation) != operationID || events[0].Reason != "limited" {
				t.Fatal("user-status admission lost exact denial attribution", events)
			}
			if out, err := limiter.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
				t.Fatal("user-status admission did not debit organization budget", err)
			}
		})
	}
}

func TestUserStatusUsesCanonicalDebitsAndRejectsInvalidAdmissions(t *testing.T) {
	f := newFixture(t)
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/admin/user-ban", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
		t.Fatal(err)
	}
	original := f.rate.last
	previousAttempt := original.CommandID
	for _, operationID := range []string{"identity.admin.user-ban", "identity.admin.user-unban"} {
		if retry, err := f.c.AdminRate.AdmitUserStatus(t.Context(), facts, operationID, "user-a"); err != nil || retry != 0 {
			t.Fatal("user-status admission failed", retry, err)
		}
		if f.rate.last.CommandID == previousAttempt || len(f.rate.last.Requests) != 3 {
			t.Fatal("user-status admission reused an attempt or split canonical budgets")
		}
		previousAttempt = f.rate.last.CommandID
		for i, before := range original.Requests {
			after := f.rate.last.Requests[i]
			if before.Key != after.Key || before.Policy.ID() != after.Policy.ID() || before.Policy.Capacity() != after.Policy.Capacity() || after.Cost != 1 {
				t.Fatal("user-status admission changed canonical actor, tenant or full-IP budgets")
			}
		}
	}
	calls := f.rate.calls
	for _, operationID := range []string{"", "user-ban", "identity.admin.ban-user", "identity.admin.user-ban ", "identity.admin.user-delete", "identity.impersonation.deny"} {
		if retry, err := f.c.AdminRate.AdmitUserStatus(t.Context(), facts, operationID, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
			t.Fatal("noncanonical user-status operation reached backend", operationID, retry, err)
		}
	}
	for _, user := range []identity.UserID{"", "with space", identity.UserID(strings.Repeat("a", 129))} {
		if retry, err := f.c.AdminRate.AdmitUserStatus(t.Context(), facts, "identity.admin.user-ban", user); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
			t.Fatal("invalid user-status actor reached backend", retry, err)
		}
	}
	if retry, err := f.c.AdminRate.AdmitUserStatus(nil, facts, "identity.admin.user-ban", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
		t.Fatal("missing user-status context reached backend", retry, err)
	}
	if retry, err := f.c.AdminRate.AdmitUserStatus(t.Context(), identityhttp.NetworkFacts{}, "identity.admin.user-unban", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
		t.Fatal("unproven user-status network facts reached backend", retry, err)
	}
	for _, operationID := range []string{"identity.admin.user-ban", "identity.admin.user-unban"} {
		if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Operation(operationID), "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != calls {
			t.Fatal("generic organization admission was broadened to user status")
		}
		if _, err := f.c.AdminRate.AdmitDirectorySync(t.Context(), facts, operationID, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != calls {
			t.Fatal("directory admission was broadened to user status")
		}
	}
	f.rate.mode = 2
	if retry, err := f.c.AdminRate.AdmitUserStatus(t.Context(), facts, "identity.admin.user-unban", "user-a"); !errors.Is(err, identityhttp.ErrRateUnavailable) || retry != 0 || f.denials.Load() != 1 {
		t.Fatal("unknown user-status admission did not fail closed with mandatory auditing", retry, err)
	}
}

func TestImpersonationQuorumSharesAdministrativeBudgetAndExactDenialAudit(t *testing.T) {
	f := newFixture(t)
	var events []organizationhttp.AdminRateEvent
	limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
		Shared: &budgetBackend{used: make(map[string]uint64)}, Namespace: "organization-test", Key: [32]byte{1},
		Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("quorum denial audit lacks its admission deadline")
			}
			events = append(events, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/impersonation/quorum", ``, true))
	if err != nil {
		t.Fatal(err)
	}
	for range 29 {
		if out, err := limiter.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
			t.Fatal("organization budget exhausted before actor capacity", err)
		}
	}
	if retry, err := limiter.AdmitImpersonationQuorum(t.Context(), facts, "user-a"); err != nil || retry != 0 || len(events) != 0 {
		t.Fatal("quorum read did not consume final shared actor token", retry, err)
	}
	if retry, err := limiter.AdmitImpersonationQuorum(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || retry != 2*time.Second {
		t.Fatal("quorum read bypassed exhausted shared budget", retry, err)
	}
	if len(events) != 1 || events[0].Operation != "identity.impersonation.quorum" || events[0].Reason != "limited" {
		t.Fatal("quorum read lost exact denial attribution", events)
	}
	if out, err := limiter.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
		t.Fatal("quorum read did not debit organization budget", err)
	}
}

func TestImpersonationQuorumUsesCanonicalDebitsAndFailsClosed(t *testing.T) {
	f := newFixture(t)
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/impersonation/quorum", ``, true))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
		t.Fatal(err)
	}
	original := f.rate.last
	if retry, err := f.c.AdminRate.AdmitImpersonationQuorum(t.Context(), facts, "user-a"); err != nil || retry != 0 {
		t.Fatal("quorum read admission failed", retry, err)
	}
	if f.rate.last.CommandID == original.CommandID || len(f.rate.last.Requests) != 3 {
		t.Fatal("quorum read reused an attempt or split canonical budgets")
	}
	for i, before := range original.Requests {
		after := f.rate.last.Requests[i]
		if before.Key != after.Key || before.Policy.ID() != after.Policy.ID() || before.Policy.Capacity() != after.Policy.Capacity() || after.Cost != 1 {
			t.Fatal("quorum read changed canonical actor, tenant or full-IP budgets")
		}
	}
	for _, user := range []identity.UserID{"", "with space", identity.UserID(strings.Repeat("a", 129))} {
		if retry, err := f.c.AdminRate.AdmitImpersonationQuorum(t.Context(), facts, user); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != 2 {
			t.Fatal("invalid quorum actor reached backend", retry, err)
		}
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, "identity.impersonation.quorum", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 2 {
		t.Fatal("generic organization admission was broadened to quorum read")
	}
	if _, err := f.c.AdminRate.AdmitDirectorySync(t.Context(), facts, "identity.impersonation.quorum", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 2 {
		t.Fatal("directory admission was broadened to quorum read")
	}
	f.rate.mode = 2
	if retry, err := f.c.AdminRate.AdmitImpersonationQuorum(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrRateUnavailable) || retry != 0 || f.denials.Load() != 1 {
		t.Fatal("unknown quorum admission did not fail closed with mandatory auditing", retry, err)
	}
}

func TestImpersonationDenySharesAdministrativeBudgetAndExactDenialAudit(t *testing.T) {
	f := newFixture(t)
	var events []organizationhttp.AdminRateEvent
	limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
		Shared: &budgetBackend{used: make(map[string]uint64)}, Namespace: "organization-test", Key: [32]byte{1},
		Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("impersonation denial audit lacks its admission deadline")
			}
			events = append(events, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	admitter, ok := any(limiter).(impersonationDenyRateAdmitter)
	if !ok {
		t.Fatal("shared administrative owner cannot admit impersonation deny")
	}
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/impersonation/deny", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	for range 29 {
		if out, err := limiter.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
			t.Fatal("organization budget exhausted before actor capacity", err)
		}
	}
	if retry, err := admitter.AdmitImpersonationDeny(t.Context(), facts, "user-a"); err != nil || retry != 0 || len(events) != 0 {
		t.Fatal("impersonation deny did not consume final shared actor token", retry, err)
	}
	if retry, err := admitter.AdmitImpersonationDeny(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || retry != 2*time.Second {
		t.Fatal("impersonation deny bypassed exhausted shared budget", retry, err)
	}
	if len(events) != 1 || events[0].Operation != "identity.impersonation.deny" || events[0].Reason != "limited" {
		t.Fatal("impersonation deny lost exact denial attribution", events)
	}
	if out, err := limiter.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
		t.Fatal("impersonation deny did not debit organization budget", err)
	}
}

func TestImpersonationDenyUsesActualBindingsAndRejectsInvalidInputs(t *testing.T) {
	f := newFixture(t)
	admitter, ok := any(f.c.AdminRate).(impersonationDenyRateAdmitter)
	if !ok {
		t.Fatal("shared administrative owner cannot admit impersonation deny")
	}
	config := f.c.Network
	config.TenantHosts = append(config.TenantHosts, identityhttp.TenantHost{Host: "other.example", TenantID: "tenant-b"})
	config.PublicHosts = []string{"public.example"}
	resolver, err := identityhttp.NewNetworkResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(host, remoteAddr string) identityhttp.NetworkFacts {
		t.Helper()
		r := request(f, "/v1/impersonation/deny", `{}`, true)
		r.Host, r.RemoteAddr = host, remoteAddr
		facts, err := resolver.Resolve(r)
		if err != nil {
			t.Fatal(err)
		}
		return facts
	}
	facts := resolve("tenant.example", "198.51.100.7:54321")
	if out, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
		t.Fatal(err)
	}
	original := f.rate.last
	previousAttempt := original.CommandID
	for _, tc := range []struct {
		name    string
		facts   identityhttp.NetworkFacts
		user    identity.UserID
		changed [3]bool
	}{
		{"same-binding", facts, "user-a", [3]bool{}},
		{"actual-actor", facts, "user-b", [3]bool{true, false, false}},
		{"actual-tenant", resolve("other.example", "198.51.100.7:54321"), "user-a", [3]bool{true, true, false}},
		{"full-ip", resolve("tenant.example", "198.51.100.8:54321"), "user-a", [3]bool{false, false, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if retry, err := admitter.AdmitImpersonationDeny(t.Context(), tc.facts, tc.user); err != nil || retry != 0 {
				t.Fatal("impersonation deny admission failed", retry, err)
			}
			if f.rate.last.CommandID == previousAttempt || len(f.rate.last.Requests) != 3 {
				t.Fatal("impersonation deny reused an attempt or split canonical budgets")
			}
			previousAttempt = f.rate.last.CommandID
			for i, before := range original.Requests {
				after := f.rate.last.Requests[i]
				if (before.Key != after.Key) != tc.changed[i] || before.Policy.ID() != after.Policy.ID() || before.Policy.Capacity() != after.Policy.Capacity() || after.Cost != 1 {
					t.Fatal("impersonation deny changed policy or ignored actual actor/tenant/full-IP binding")
				}
			}
		})
	}
	calls := f.rate.calls
	for _, user := range []identity.UserID{"", "with space", identity.UserID(strings.Repeat("a", 129))} {
		if retry, err := admitter.AdmitImpersonationDeny(t.Context(), facts, user); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
			t.Fatal("invalid impersonation actor reached backend", retry, err)
		}
	}
	for _, invalid := range []identityhttp.NetworkFacts{{}, resolve("public.example", "198.51.100.7:54321")} {
		if retry, err := admitter.AdmitImpersonationDeny(t.Context(), invalid, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
			t.Fatal("unproven tenant facts reached backend", retry, err)
		}
	}
	if retry, err := admitter.AdmitImpersonationDeny(nil, facts, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
		t.Fatal("missing context reached backend", retry, err)
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, "identity.impersonation.deny", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != calls {
		t.Fatal("generic organization admission was broadened to impersonation deny")
	}
	if _, err := f.c.AdminRate.AdmitDirectorySync(t.Context(), facts, "identity.impersonation.deny", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != calls {
		t.Fatal("directory admission was broadened to impersonation deny")
	}
	var nilLimiter *organizationhttp.AdminRateLimiter
	for _, limiter := range []*organizationhttp.AdminRateLimiter{nilLimiter, {}, f.c.AdminRate} {
		if limiter == f.c.AdminRate {
			if err := limiter.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if retry, err := any(limiter).(impersonationDenyRateAdmitter).AdmitImpersonationDeny(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || retry != 0 || f.rate.calls != calls {
			t.Fatal("unconfigured or closed impersonation admission reached backend", retry, err)
		}
	}
}

func TestImpersonationDenyAuditsUnavailableAndFailsClosed(t *testing.T) {
	for _, mode := range []string{"unknown-backend", "unavailable-backend", "panic-backend", "failed-audit", "panic-audit", "canceled-context"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			var events []organizationhttp.AdminRateEvent
			limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: f.rate, Namespace: "organization-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
				Denied: func(_ context.Context, event organizationhttp.AdminRateEvent) error {
					events = append(events, event)
					if mode == "failed-audit" {
						return errors.New("private audit diagnostic")
					}
					if mode == "panic-audit" {
						panic("private audit diagnostic")
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { limiter.Close() })
			admitter, ok := any(limiter).(impersonationDenyRateAdmitter)
			if !ok {
				t.Fatal("shared administrative owner cannot admit impersonation deny")
			}
			switch mode {
			case "unknown-backend":
				f.rate.mode = 2
			case "unavailable-backend":
				f.rate.mode = 3
			case "panic-backend":
				f.rate.mode = 4
			default:
				f.rate.mode = 1
			}
			resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := resolver.Resolve(request(f, "/v1/impersonation/deny", `{}`, true))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "canceled-context" {
				cancel()
			}
			retry, err := admitter.AdmitImpersonationDeny(ctx, facts, "user-a")
			if !errors.Is(err, identityhttp.ErrRateUnavailable) || retry != 0 || strings.Contains(fmt.Sprint(err), "private") {
				t.Fatal("impersonation deny failed open or leaked private diagnostics", retry, err)
			}
			wantReason := "unavailable"
			if mode == "failed-audit" || mode == "panic-audit" {
				wantReason = "limited"
			}
			if len(events) != 1 || events[0].Operation != "identity.impersonation.deny" || events[0].Reason != wantReason {
				t.Fatal("impersonation deny escaped exact mandatory denial auditing", events)
			}
		})
	}
}

func TestSCIMConnectionCreateSharesAdministrativeBudgetAndExactDenialAudit(t *testing.T) {
	f := newFixture(t)
	var events []organizationhttp.AdminRateEvent
	limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
		Shared: &budgetBackend{used: make(map[string]uint64)}, Namespace: "organization-test", Key: [32]byte{1},
		Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("SCIM denial audit lacks its admission deadline")
			}
			events = append(events, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	admitter, ok := any(limiter).(scimCreateRateAdmitter)
	if !ok {
		t.Fatal("shared administrative owner cannot admit SCIM connection create")
	}
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/scim/connection-create", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	for range 29 {
		if out, err := limiter.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
			t.Fatal("organization budget exhausted before actor capacity", err)
		}
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, "user-a"); err != nil || !out.Allowed || out.RetryAfter != 0 {
		t.Fatal("SCIM create did not use final shared actor token", err)
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 2*time.Second {
		t.Fatal("SCIM create bypassed exhausted shared budget", err)
	}
	if len(events) != 1 || events[0].Operation != "identity.scim.connection-create" || events[0].Reason != "limited" {
		t.Fatal("SCIM create denial lost exact operation attribution")
	}
	if out, err := limiter.Admit(t.Context(), facts, organization.RemoveMember, "user-a"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
		t.Fatal("SCIM create did not debit organization budget", err)
	}
}

func TestSCIMConnectionCreateAdmissionUsesFreshCanonicalDebitsAndFiniteInputs(t *testing.T) {
	f := newFixture(t)
	admitter, ok := any(f.c.AdminRate).(scimCreateRateAdmitter)
	if !ok {
		t.Fatal("shared administrative owner cannot admit SCIM connection create")
	}
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/scim/connection-create", `{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Create, "user-a"); err != nil || !out.Allowed {
		t.Fatal(err)
	}
	original := f.rate.last
	for range 2 {
		if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, "user-a"); err != nil || !out.Allowed {
			t.Fatal("SCIM create admission failed", err)
		}
		if f.rate.last.CommandID == original.CommandID {
			t.Fatal("SCIM create reused an earlier attempt identity")
		}
		for i, before := range original.Requests {
			after := f.rate.last.Requests[i]
			if before.Key != after.Key || before.Policy.ID() != after.Policy.ID() || before.Policy.Capacity() != after.Policy.Capacity() || after.Cost != 1 {
				t.Fatal("SCIM create changed canonical organization buckets")
			}
		}
		original = f.rate.last
	}
	for _, user := range []identity.UserID{"", "with space", identity.UserID(strings.Repeat("a", 129))} {
		if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, user); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (organizationhttp.AdminRateResult{}) || f.rate.calls != 3 {
			t.Fatal("invalid actor reached the shared backend")
		}
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), identityhttp.NetworkFacts{}, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (organizationhttp.AdminRateResult{}) || f.rate.calls != 3 {
		t.Fatal("unproven tenant/network reached shared backend")
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(nil, facts, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (organizationhttp.AdminRateResult{}) || f.rate.calls != 3 {
		t.Fatal("missing request context reached shared backend")
	}
	publicConfig := f.c.Network
	publicConfig.PublicHosts = []string{"public.example"}
	publicResolver, err := identityhttp.NewNetworkResolver(publicConfig)
	if err != nil {
		t.Fatal(err)
	}
	publicRequest := request(f, "/v1/scim/connection-create", `{}`, true)
	publicRequest.Host = "public.example"
	publicFacts, err := publicResolver.Resolve(publicRequest)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), publicFacts, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (organizationhttp.AdminRateResult{}) || f.rate.calls != 3 {
		t.Fatal("public realm became an administrative tenant")
	}
	if _, err := f.c.AdminRate.Admit(t.Context(), facts, organization.Operation("identity.scim.connection-create"), "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 3 {
		t.Fatal("organization admission was broadened to SCIM")
	}
	if _, err := f.c.AdminRate.AdmitDirectorySync(t.Context(), facts, "identity.scim.connection-create", "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || f.rate.calls != 3 {
		t.Fatal("directory admission was broadened to SCIM")
	}
	if err := f.c.AdminRate.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (organizationhttp.AdminRateResult{}) || f.rate.calls != 3 {
		t.Fatal("closed SCIM admission reached backend")
	}
}

func TestSCIMConnectionCreateAdmissionAuditsUnavailableAndFailsClosed(t *testing.T) {
	for _, mode := range []string{"unknown-backend", "unavailable-backend", "panic-backend", "failed-audit", "panic-audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			var events []organizationhttp.AdminRateEvent
			limiter, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: f.rate, Namespace: "organization-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second,
				Denied: func(_ context.Context, event organizationhttp.AdminRateEvent) error {
					events = append(events, event)
					if mode == "failed-audit" {
						return errors.New("private audit diagnostic")
					}
					if mode == "panic-audit" {
						panic("private audit diagnostic")
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { limiter.Close() })
			admitter, ok := any(limiter).(scimCreateRateAdmitter)
			if !ok {
				t.Fatal("shared administrative owner cannot admit SCIM connection create")
			}
			switch mode {
			case "unknown-backend":
				f.rate.mode = 2
			case "unavailable-backend":
				f.rate.mode = 3
			case "panic-backend":
				f.rate.mode = 4
			default:
				f.rate.mode = 1
			}
			resolver, _ := identityhttp.NewNetworkResolver(f.c.Network)
			facts, _ := resolver.Resolve(request(f, "/v1/scim/connection-create", `{}`, true))
			out, err := admitter.AdmitSCIMConnectionCreate(t.Context(), facts, "user-a")
			if !errors.Is(err, identityhttp.ErrRateUnavailable) || out != (organizationhttp.AdminRateResult{}) || strings.Contains(fmt.Sprint(err), "private") {
				t.Fatal("SCIM admission failed open or leaked private diagnostics", err)
			}
			wantReason := "unavailable"
			if mode == "failed-audit" || mode == "panic-audit" {
				wantReason = "limited"
			}
			if len(events) != 1 || events[0].Operation != "identity.scim.connection-create" || events[0].Reason != wantReason {
				t.Fatal("SCIM failure escaped exact mandatory denial auditing")
			}
		})
	}
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
