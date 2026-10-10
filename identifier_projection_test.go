package identity_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func identifierProjectionFixture() identity.IdentifierProjectionSpec {
	now := time.Date(2026, 10, 10, 19, 0, 0, 0, time.UTC)
	return identity.IdentifierProjectionSpec{
		TenantID: "tenant-one", UserID: "01K6TAM7DG1G04NMKXBPMVKPHG", IdentifierID: "address-one",
		ObservedAt: now, Values: identity.IdentifierValuesIncluded,
		State: identity.IdentifierState{
			User: identity.User{ID: "01K6TAM7DG1G04NMKXBPMVKPHG", TenantID: "tenant-one", Status: identity.StatusActive, Version: 11}, AuthorityVersion: 7,
			Identifiers: []identity.Identifier{
				{ID: "address-one", UserID: "01K6TAM7DG1G04NMKXBPMVKPHG", Kind: identity.IdentifierEmail, CanonicalValue: "one@example.test", DisplayValue: "One@example.test", Verified: true, Primary: true, Version: 3},
				{ID: "provider-two", UserID: "01K6TAM7DG1G04NMKXBPMVKPHG", Kind: identity.IdentifierProviderSubject, CanonicalValue: "exact provider subject", Version: 9},
			},
			Verifications: []identity.Verification{
				{IdentifierID: "address-one", State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 5},
				{IdentifierID: "provider-two", State: identity.VerificationPending, Version: 2},
			},
		},
	}
}

func TestIdentifierProjectionPreservesScopedImmutableSnapshot(t *testing.T) {
	s := identifierProjectionFixture()
	p, err := identity.NewIdentifierProjection(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Bindings()
	if err != nil || b.TenantID != s.TenantID || b.UserID != s.UserID || b.IdentifierID != s.IdentifierID || b.Kind != identity.IdentifierEmail || !b.Verified || !b.Primary || b.UserVersion != 11 || b.AuthorityVersion != 7 || b.IdentifierVersion != 3 || b.VerificationVersion != 5 || b.Status != identity.StatusActive || b.VerificationState != identity.VerificationVerified || !b.ObservedAt.Equal(s.ObservedAt) || !b.VerifiedAt.Equal(s.State.Verifications[0].VerifiedAt) {
		t.Fatal("projection confused scope, independent versions or observation", err)
	}
	canonical, display, present := p.Values()
	if !present || canonical != "one@example.test" || display != "One@example.test" {
		t.Fatal("selected address values changed")
	}
	s.State.Identifiers[0].CanonicalValue = "mutated@example.test"
	s.State.Verifications[0].Version = 100
	b.UserVersion = 100
	copy := p
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			b, err := copy.Bindings()
			value, display, present := copy.Values()
			if err != nil || b.UserVersion != 11 || b.VerificationVersion != 5 || !present || value != canonical || display != "One@example.test" {
				t.Error("source or returned metadata mutation changed immutable snapshot")
			}
		})
	}
	wait.Wait()
}

func TestIdentifierProjectionPendingRevokedKindsAndVisibility(t *testing.T) {
	for _, kind := range []identity.IdentifierKind{identity.IdentifierEmail, identity.IdentifierPhone, identity.IdentifierUsername, identity.IdentifierProviderSubject} {
		for _, state := range []identity.VerificationState{identity.VerificationPending, identity.VerificationRevoked} {
			s := identifierProjectionFixture()
			s.IdentifierID = "provider-two"
			s.State.Identifiers[1].Kind = kind
			s.State.Verifications[1].State = state
			s.State.User.Status = identity.StatusBanned // An authorized admin may inspect historical metadata.
			p, err := identity.NewIdentifierProjection(s)
			b, bindErr := p.Bindings()
			canonical, display, present := p.Values()
			if err != nil || bindErr != nil || b.Verified || b.Primary || b.Kind != kind || b.VerificationState != state || b.Status != identity.StatusBanned || !present || canonical != "exact provider subject" || display != "" {
				t.Fatal("projection invented verification or normalized an identifier", err, bindErr)
			}
		}
	}
	s := identifierProjectionFixture()
	s.Values = identity.IdentifierValuesOmitted
	p, err := identity.NewIdentifierProjection(s)
	canonical, display, present := p.Values()
	b, bindErr := p.Bindings()
	if err != nil || bindErr != nil || canonical != "" || display != "" || present || b.Values != identity.IdentifierValuesOmitted || !b.Verified {
		t.Fatal("redacted projection retained values or lost safe metadata", err, bindErr)
	}
	s.State.Identifiers[0].CanonicalValue = strings.Repeat("x", 512)
	s.Values = identity.IdentifierValuesIncluded
	if _, err := identity.NewIdentifierProjection(s); err != nil {
		t.Fatal("maximum bounded value rejected", err)
	}
	s.State.User.Version, s.State.AuthorityVersion = ^uint64(0), ^uint64(0)
	s.State.Identifiers[0].Version, s.State.Verifications[0].Version = ^uint64(0), ^uint64(0)
	if _, err := identity.NewIdentifierProjection(s); err != nil {
		t.Fatal("read-only snapshot incorrectly required next-version capacity", err)
	}
}

func TestIdentifierProjectionRejectsInconsistentPartitions(t *testing.T) {
	for name, change := range map[string]func(*identity.IdentifierProjectionSpec){
		"tenant":         func(s *identity.IdentifierProjectionSpec) { s.TenantID = "other" },
		"user":           func(s *identity.IdentifierProjectionSpec) { s.UserID = "other" },
		"missing target": func(s *identity.IdentifierProjectionSpec) { s.IdentifierID = "missing" },
		"zero target":    func(s *identity.IdentifierProjectionSpec) { s.IdentifierID = "" },
		"zero policy":    func(s *identity.IdentifierProjectionSpec) { s.Values = 0 },
		"unknown policy": func(s *identity.IdentifierProjectionSpec) { s.Values = 99 },
		"zero time":      func(s *identity.IdentifierProjectionSpec) { s.ObservedAt = time.Time{} },
		"invalid time": func(s *identity.IdentifierProjectionSpec) {
			s.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"zero user version":         func(s *identity.IdentifierProjectionSpec) { s.State.User.Version = 0 },
		"zero authority":            func(s *identity.IdentifierProjectionSpec) { s.State.AuthorityVersion = 0 },
		"zero identifier version":   func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[0].Version = 0 },
		"zero verification version": func(s *identity.IdentifierProjectionSpec) { s.State.Verifications[0].Version = 0 },
		"future verification": func(s *identity.IdentifierProjectionSpec) {
			s.State.Verifications[0].VerifiedAt = s.ObservedAt.Add(time.Second)
		},
		"mismatched verification": func(s *identity.IdentifierProjectionSpec) { s.State.Verifications[0].IdentifierID = "other" },
		"missing verification":    func(s *identity.IdentifierProjectionSpec) { s.State.Verifications = s.State.Verifications[:1] },
		"unverified primary":      func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[0].Verified = false },
		"non-target owner":        func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[1].UserID = "other" },
		"duplicate ID":            func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[1].ID = s.State.Identifiers[0].ID },
		"unordered IDs": func(s *identity.IdentifierProjectionSpec) {
			slices.Reverse(s.State.Identifiers)
			slices.Reverse(s.State.Verifications)
		},
		"duplicate values": func(s *identity.IdentifierProjectionSpec) {
			s.State.Identifiers[1].Kind = identity.IdentifierEmail
			s.State.Identifiers[1].CanonicalValue = s.State.Identifiers[0].CanonicalValue
		},
		"two primaries": func(s *identity.IdentifierProjectionSpec) {
			s.State.Identifiers[1].Kind = identity.IdentifierEmail
			s.State.Identifiers[1].Verified = true
			s.State.Identifiers[1].Primary = true
			s.State.Verifications[1].State = identity.VerificationVerified
			s.State.Verifications[1].VerifiedAt = s.ObservedAt
		},
		"oversized": func(s *identity.IdentifierProjectionSpec) {
			s.State.Identifiers[0].CanonicalValue = strings.Repeat("x", 513)
		},
		"malformed UTF8": func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[0].CanonicalValue = "\xff" },
		"control":        func(s *identity.IdentifierProjectionSpec) { s.State.Identifiers[0].DisplayValue = "value\n" },
	} {
		t.Run(name, func(t *testing.T) {
			s := identifierProjectionFixture()
			change(&s)
			p, err := identity.NewIdentifierProjection(s)
			var invalid identity.InvalidInputError
			if !errors.As(err, &invalid) || p != (identity.IdentifierProjection{}) {
				t.Fatal("inconsistent partition yielded usable projection", err)
			}
		})
	}
	var zero identity.IdentifierProjection
	if b, err := zero.Bindings(); err == nil || b != (identity.IdentifierProjectionBindings{}) {
		t.Fatal("zero projection yielded metadata")
	}
	if a, d, present := zero.Values(); a != "" || d != "" || present {
		t.Fatal("zero projection yielded values")
	}
}

func TestIdentifierProjectionDiagnosticsAndSerializationStayClosed(t *testing.T) {
	s := identifierProjectionFixture()
	p, err := identity.NewIdentifierProjection(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{p, &p, struct{ private identity.IdentifierProjection }{p}, s} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
			out := fmt.Sprintf(format, value)
			for _, sensitive := range []string{"tenant-one", "01K6TAM7DG1G04NMKXBPMVKPHG", "address-one", "one@example.test", "One@example.test", "exact provider subject"} {
				if strings.Contains(out, sensitive) {
					t.Fatal("diagnostics disclosed projection input")
				}
			}
		}
	}
	for _, value := range []any{p, &p, s} {
		if wire, err := json.Marshal(value); err == nil || len(wire) != 0 {
			t.Fatal("implicit JSON export permitted")
		}
	}
	if p.LogValue().Kind() != slog.KindString || strings.Contains(p.LogValue().String(), "example") {
		t.Fatal("structured log disclosed address")
	}
	if wire, err := p.MarshalText(); err == nil || len(wire) != 0 {
		t.Fatal("implicit text export permitted")
	}
	if wire, err := s.MarshalText(); err == nil || len(wire) != 0 {
		t.Fatal("implicit spec export permitted")
	}
}
