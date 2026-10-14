package identity_test

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-identity"
)

func TestUserValidationPreservesIdentityAndTenant(t *testing.T) {
	u := identity.User{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", TenantID: "tenant-a", Status: identity.StatusActive, Version: 7}
	before := u
	if err := u.Validate("tenant-a"); err != nil || u != before {
		t.Fatalf("canonical imported identity changed or was rejected: %v", err)
	}
	if err := u.Validate("tenant-b"); err == nil {
		t.Fatal("cross-tenant projection accepted")
	}
	for _, status := range []identity.Status{identity.StatusActive, identity.StatusSuspended, identity.StatusBanned, identity.StatusAnonymized, identity.StatusDeleted} {
		u.Status = status
		if err := u.Validate("tenant-a"); err != nil {
			t.Fatal(err)
		}
		if status.AllowsAuthentication() != (status == identity.StatusActive) {
			t.Fatal("non-active status admitted authentication")
		}
	}
}

func TestUserValidationRejectsMalformedProjectionsWithoutDisclosure(t *testing.T) {
	valid := identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}
	for _, raw := range []string{"", strings.Repeat("x", 129), "user\ncredential", " user", "user\x7f", "\xff"} {
		u := valid
		u.ID = identity.UserID(raw)
		assertInvalid(t, u.Validate("tenant-a"))
		u = valid
		u.TenantID = identity.TenantID(raw)
		assertInvalid(t, u.Validate(identity.TenantID(raw)))
		assertInvalid(t, valid.Validate(identity.TenantID(raw)))
	}
	for _, status := range []identity.Status{"", "caller-invented"} {
		u := valid
		u.Status = status
		assertInvalid(t, u.Validate("tenant-a"))
		if status.AllowsAuthentication() {
			t.Fatal("unknown status admitted authentication")
		}
	}
	valid.Version = 0
	assertInvalid(t, valid.Validate("tenant-a"))
}

func TestStatusPolicyDeniesUnlistedAndTerminalTransitions(t *testing.T) {
	p := lifecyclePolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, from := range []identity.Status{identity.StatusActive, identity.StatusSuspended, identity.StatusBanned, identity.StatusAnonymized, identity.StatusDeleted} {
		for _, to := range []identity.Status{identity.StatusActive, identity.StatusSuspended, identity.StatusBanned, identity.StatusAnonymized, identity.StatusDeleted} {
			allowed := from == identity.StatusActive && (to == identity.StatusSuspended || to == identity.StatusBanned) || from == identity.StatusSuspended && to == identity.StatusActive || from == identity.StatusAnonymized && to == identity.StatusDeleted
			if got := p.CheckTransition(from, to, true, 0); (got == nil) != allowed {
				t.Fatalf("transition %q -> %q result %v, expected allowed=%v", from, to, got, allowed)
			}
		}
	}
	assertInvalid(t, p.CheckTransition("unknown", identity.StatusActive, true, 0))
	assertInvalid(t, p.CheckTransition(identity.StatusActive, "unknown", true, 0))
}

func TestStatusPolicyRequiresReasonsAndBoundsTemporaryRestrictions(t *testing.T) {
	p := lifecyclePolicy()
	assertInvalid(t, p.CheckTransition(identity.StatusActive, identity.StatusSuspended, false, time.Hour))
	assertInvalid(t, p.CheckTransition(identity.StatusActive, identity.StatusBanned, false, 0))
	assertInvalid(t, p.CheckTransition(identity.StatusActive, identity.StatusBanned, true, -1))
	assertInvalid(t, p.CheckTransition(identity.StatusActive, identity.StatusBanned, true, p.MaximumSuspension+1))
	assertInvalid(t, p.CheckTransition(identity.StatusSuspended, identity.StatusActive, true, time.Second))
	for _, duration := range []time.Duration{0, 1, p.MaximumSuspension} {
		if err := p.CheckTransition(identity.StatusActive, identity.StatusBanned, true, duration); err != nil {
			t.Fatal(err)
		}
	}
	p.BanRequiresReason = false
	if err := p.CheckTransition(identity.StatusActive, identity.StatusBanned, false, 0); err != nil {
		t.Fatal("explicit optional ban reason ignored")
	}
}

func TestStatusPolicyRejectsInvalidConfiguration(t *testing.T) {
	for _, mutate := range []func(*identity.StatusPolicy){
		func(p *identity.StatusPolicy) { p.AllowedTransitions = nil },
		func(p *identity.StatusPolicy) { p.AllowedTransitions = make([]identity.StatusTransition, 33) },
		func(p *identity.StatusPolicy) {
			p.AllowedTransitions = append(p.AllowedTransitions, p.AllowedTransitions[0])
		},
		func(p *identity.StatusPolicy) { p.AllowedTransitions[0].From = "unknown" },
		func(p *identity.StatusPolicy) { p.AllowedTransitions[0].To = "unknown" },
		func(p *identity.StatusPolicy) { p.AllowedTransitions[0].To = identity.StatusActive },
		func(p *identity.StatusPolicy) { p.AllowedTransitions[0].From = identity.StatusDeleted },
		func(p *identity.StatusPolicy) { p.AllowedTransitions[0].From = identity.StatusAnonymized },
		func(p *identity.StatusPolicy) { p.MaximumSuspension = 0 },
		func(p *identity.StatusPolicy) { p.MaximumSuspension = -1 },
		func(p *identity.StatusPolicy) { p.MaximumSuspension = 87600*time.Hour + 1 },
		func(p *identity.StatusPolicy) { p.IdentifierReuseCooldown = -1 },
		func(p *identity.StatusPolicy) { p.IdentifierReuseCooldown = 87600*time.Hour + 1 },
	} {
		p := lifecyclePolicy()
		mutate(&p)
		assertInvalid(t, p.Validate())
		assertInvalid(t, p.CheckTransition(identity.StatusActive, identity.StatusBanned, true, 0))
	}
	p := lifecyclePolicy()
	p.MaximumSuspension = 87600 * time.Hour
	p.IdentifierReuseCooldown = p.MaximumSuspension
	if err := p.Validate(); err != nil {
		t.Fatal("inclusive maximum rejected")
	}
}

func TestDirectoryBoundaryAndReadOnlyPolicy(t *testing.T) {
	u := identity.User{ID: identity.UserID(strings.Repeat("x", 128)), TenantID: identity.TenantID(strings.Repeat("y", 128)), Status: identity.StatusActive, Version: ^uint64(0)}
	if err := u.Validate(u.TenantID); err != nil {
		t.Fatal("inclusive identity/version boundary rejected")
	}
	p := lifecyclePolicy()
	for range 16 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()
			for range 32 {
				if err := u.Validate(u.TenantID); err != nil {
					t.Fatal(err)
				}
				if err := p.CheckTransition(identity.StatusSuspended, identity.StatusActive, false, 0); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func FuzzUserValidation(f *testing.F) {
	for _, seed := range []string{"", "user-a", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "\x00\xff", "leading space ", strings.Repeat("a", 128), strings.Repeat("a", 129)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		valid := len(raw) > 0 && len(raw) <= 128 && utf8.ValidString(raw)
		if valid {
			for i := range len(raw) {
				if raw[i] <= 0x20 || raw[i] == 0x7f {
					valid = false
				}
			}
		}
		u := identity.User{ID: identity.UserID(raw), TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}
		before := u
		if err := u.Validate("tenant-a"); (err == nil) != valid || u != before {
			t.Fatal("validation diverged or changed identity")
		}
		u.ID = "user-a"
		u.TenantID = identity.TenantID(raw)
		if err := u.Validate(identity.TenantID(raw)); (err == nil) != valid {
			t.Fatal("tenant validation diverged")
		}
	})
}

func lifecyclePolicy() identity.StatusPolicy {
	return identity.StatusPolicy{
		AllowedTransitions: []identity.StatusTransition{
			{From: identity.StatusActive, To: identity.StatusSuspended, ReasonRequired: true},
			{From: identity.StatusActive, To: identity.StatusBanned},
			{From: identity.StatusSuspended, To: identity.StatusActive},
			{From: identity.StatusAnonymized, To: identity.StatusDeleted},
		},
		MaximumSuspension: time.Hour, BanRequiresReason: true,
	}
}

func assertInvalid(t *testing.T, err error) {
	t.Helper()
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field == "" || err.Error() != "identity: invalid input" {
		t.Fatalf("expected classified redacted validation error, got %v", err)
	}
}
