package anonymous_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
)

func TestAnonymousPolicyReservesNonContactNamespaceAndBounds(t *testing.T) {
	config := anonymous.Config{DisplayName: "Gue\u0301st", PlaceholderEmailDomain: "anonymous.invalid", TTL: 24 * time.Hour, Cleanup: anonymous.CleanupAnonymize}
	policy, err := anonymous.NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Config()
	if err != nil || got.DisplayName != "Guést" || got.PlaceholderEmailDomain != "anonymous.invalid" || got.TTL != 24*time.Hour || got.Cleanup != anonymous.CleanupAnonymize {
		t.Fatal("anonymous policy changed or skipped normalization", err)
	}
	for _, mutate := range []func(*anonymous.Config){
		func(c *anonymous.Config) { c.DisplayName = "" },
		func(c *anonymous.Config) { c.DisplayName = strings.Repeat("x", 65) },
		func(c *anonymous.Config) { c.DisplayName = "Guest\n" },
		func(c *anonymous.Config) { c.DisplayName = "\xff" },
		func(c *anonymous.Config) { c.DisplayName = "   " },
		func(c *anonymous.Config) { c.PlaceholderEmailDomain = "example.test" },
		func(c *anonymous.Config) { c.PlaceholderEmailDomain = "Anonymous.Invalid" },
		func(c *anonymous.Config) { c.TTL = 15*time.Minute - time.Nanosecond },
		func(c *anonymous.Config) { c.TTL = 30*24*time.Hour + time.Nanosecond },
		func(c *anonymous.Config) { c.Cleanup = 0 },
	} {
		bad := config
		mutate(&bad)
		if _, err := anonymous.NewPolicy(bad); err == nil {
			t.Fatal("unsafe anonymous policy admitted")
		}
	}
	if _, err := (anonymous.Policy{}).Config(); err == nil {
		t.Fatal("zero policy admitted")
	}
}

func TestAnonymousSubjectPreservesOwnerScopeStateAndAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	id, _ := identity.NewSubjectID()
	spec := anonymous.SubjectSpec{ID: id, TenantID: "tenant-a", UserID: identity.UserID(id), CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupAnonymize}
	subject, err := anonymous.NewAnonymousSubject(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := subject.Record()
	if err != nil || got != spec {
		t.Fatal("anonymous source changed", err)
	}
	if err := subject.RequireActive("tenant-a", now); err != nil {
		t.Fatal(err)
	}
	if err := subject.RequireActive("tenant-a", now.Add(time.Nanosecond)); err != nil {
		t.Fatal("trusted clock precision was restricted to database storage precision", err)
	}
	for _, test := range []struct {
		tenant identity.TenantID
		at     time.Time
	}{{"tenant-b", now}, {"tenant-a", now.Add(-time.Microsecond)}, {"tenant-a", spec.ExpiresAt}, {"tenant-a", time.Time{}}} {
		if err := subject.RequireActive(test.tenant, test.at); err == nil {
			t.Fatal("foreign or expired anonymous subject accepted")
		}
	}
	for _, state := range []anonymous.State{anonymous.StateUpgraded, anonymous.StateDeleted, anonymous.StateExpired, anonymous.StateAnonymized, anonymous.StateRetained} {
		terminal := spec
		terminal.State, terminal.Version = state, 2
		s, err := anonymous.NewAnonymousSubject(terminal)
		if err != nil {
			t.Fatal("historical terminal state lost", err)
		}
		if err := s.RequireActive(spec.TenantID, now); err == nil {
			t.Fatal("terminal anonymous state reactivated")
		}
	}
	for _, mutate := range []func(*anonymous.SubjectSpec){
		func(s *anonymous.SubjectSpec) { s.ID = "named-guest" },
		func(s *anonymous.SubjectSpec) { s.UserID = "another" },
		func(s *anonymous.SubjectSpec) { s.TenantID = "" },
		func(s *anonymous.SubjectSpec) { s.CreatedAt = s.CreatedAt.Add(time.Nanosecond) },
		func(s *anonymous.SubjectSpec) { s.ExpiresAt = s.CreatedAt.Add(14 * time.Minute) },
		func(s *anonymous.SubjectSpec) { s.ExpiresAt = s.CreatedAt.Add(31 * 24 * time.Hour) },
		func(s *anonymous.SubjectSpec) { s.State = 0 },
		func(s *anonymous.SubjectSpec) { s.Version = 0 },
		func(s *anonymous.SubjectSpec) { s.State = anonymous.StateDeleted },
		func(s *anonymous.SubjectSpec) { s.Cleanup = 0 },
	} {
		bad := spec
		mutate(&bad)
		if _, err := anonymous.NewAnonymousSubject(bad); err == nil {
			t.Fatal("malformed anonymous record accepted")
		}
	}
	if _, err := (anonymous.AnonymousSubject{}).Record(); err == nil {
		t.Fatal("zero subject projected")
	}
	if text := fmt.Sprintf("%#v", subject); strings.Contains(text, string(id)) || strings.Contains(text, "tenant-a") {
		t.Fatal("anonymous identity disclosed in diagnostics")
	}
	if _, err := json.Marshal(subject); err == nil {
		t.Fatal("anonymous metadata implicitly serialized")
	}
}

func TestAnonymousPolicyPreservesDatabaseLifetimePrecision(t *testing.T) {
	for _, ttl := range []time.Duration{15 * time.Minute, 24*time.Hour + time.Microsecond, 30 * 24 * time.Hour} {
		policy, err := anonymous.NewPolicy(anonymous.Config{DisplayName: "Guest", PlaceholderEmailDomain: "anonymous.invalid", TTL: ttl, Cleanup: anonymous.CleanupAnonymize})
		if err != nil {
			t.Fatal("database-representable lifetime rejected", err)
		}
		config, err := policy.Config()
		if err != nil || config.TTL != ttl {
			t.Fatal("lifetime precision silently changed", err)
		}
		id, _ := identity.NewSubjectID()
		created := time.Date(2026, 10, 21, 0, 0, 0, 123456000, time.UTC)
		if _, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: id, TenantID: "tenant-a", UserID: identity.UserID(id), CreatedAt: created, ExpiresAt: created.Add(config.TTL), State: anonymous.StateActive, Version: 1, Cleanup: config.Cleanup}); err != nil {
			t.Fatal("accepted policy cannot construct its original stored subject", err)
		}
	}
	for _, ttl := range []time.Duration{15*time.Minute + time.Nanosecond, 24*time.Hour + 999*time.Nanosecond, 30*24*time.Hour - time.Nanosecond} {
		if _, err := anonymous.NewPolicy(anonymous.Config{DisplayName: "Guest", PlaceholderEmailDomain: "anonymous.invalid", TTL: ttl, Cleanup: anonymous.CleanupAnonymize}); err != anonymous.ErrInvalidInput {
			t.Fatal("policy accepted a lifetime the database cannot preserve", err)
		}
	}
}
