package identity_test

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestCredentialAuthorityRequiresBothVersions(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	credential := identity.CredentialRef{ID: "password-a", TenantID: "tenant-a", UserID: "user-a", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 2}
	current := identity.CredentialAuthorityRecord{User: identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 33}, AuthorityVersion: 7, Credential: credential, Enabled: true}
	if err := identity.CheckCredentialAuthority(current, credential, 7, now); err != nil {
		t.Fatal("exact active credential denied", err)
	}
	if err := identity.CheckCredentialAuthority(current, credential, 6, now); err == nil {
		t.Fatal("old user-wide credential epoch accepted")
	}
	credential.Version = 1
	if err := identity.CheckCredentialAuthority(current, credential, 7, now); err == nil {
		t.Fatal("old credential record version accepted")
	}
}

func TestCredentialAuthorityEligibility(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	expected := identity.CredentialRef{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", TenantID: "tenant-a", UserID: "user-a", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 2}
	base := identity.CredentialAuthorityRecord{User: identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 33}, AuthorityVersion: 7, Credential: expected, Enabled: true, ExpiresAt: now.Add(time.Minute)}
	cases := []struct {
		name string
		edit func(*identity.CredentialAuthorityRecord, *identity.CredentialRef, *uint64, *time.Time)
	}{
		{"zero clock", func(_ *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, n *time.Time) {
			*n = time.Time{}
		}},
		{"out of range clock", func(_ *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, n *time.Time) {
			*n = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"invalid expected", func(_ *identity.CredentialAuthorityRecord, e *identity.CredentialRef, _ *uint64, _ *time.Time) {
			e.ID = ""
		}},
		{"foreign tenant", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.User.TenantID = "other"
		}},
		{"foreign user", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.User.ID = "other"
		}},
		{"invalid user", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.User.Version = 0
		}},
		{"foreign credential", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.Credential.UserID = "other"
		}},
		{"different credential", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.Credential.ID = "other"
		}},
		{"wrong owner", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.Credential.Owner = "consumer"
		}},
		{"different valid kind", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.Credential.Kind, r.Credential.Owner = identity.CredentialPasskey, "passkey"
		}},
		{"disabled", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.Enabled = false
		}},
		{"zero original epoch", func(_ *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, a *uint64, _ *time.Time) {
			*a = 0
		}},
		{"zero current epoch", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.AuthorityVersion = 0
		}},
		{"newer current epoch", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.AuthorityVersion++
		}},
		{"exclusive expiry", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.ExpiresAt = now
		}},
		{"expired", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.ExpiresAt = now.Add(-time.Microsecond)
		}},
		{"lossy expiry", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.ExpiresAt = now.Add(time.Nanosecond)
		}},
		{"out of range expiry", func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	}
	for _, status := range []identity.Status{identity.StatusSuspended, identity.StatusBanned, identity.StatusDeleted, identity.StatusAnonymized, "unknown", ""} {
		cases = append(cases, struct {
			name string
			edit func(*identity.CredentialAuthorityRecord, *identity.CredentialRef, *uint64, *time.Time)
		}{"status " + string(status), func(r *identity.CredentialAuthorityRecord, _ *identity.CredentialRef, _ *uint64, _ *time.Time) {
			r.User.Status = status
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, e, epoch, instant := base, expected, uint64(7), now
			tc.edit(&r, &e, &epoch, &instant)
			before := r
			err := identity.CheckCredentialAuthority(r, e, epoch, instant)
			if !errors.Is(err, identity.ErrCredentialAuthority) || err.Error() != "identity: credential authority denied" || r != before {
				t.Fatal("denial changed state or disclosed its cause", err)
			}
		})
	}
	for _, kindOwner := range []struct {
		kind  identity.CredentialKind
		owner string
	}{{identity.CredentialPassword, "identity/password"}, {identity.CredentialPasskey, "passkey"}, {identity.CredentialPasskey, "webauthn"}, {identity.CredentialProvider, "sso"}, {identity.CredentialProvider, "identity/oauth"}, {identity.CredentialAPIKey, "identity/apikey"}} {
		r, e := base, expected
		e.Kind, e.Owner = kindOwner.kind, kindOwner.owner
		r.Credential, r.ExpiresAt = e, time.Time{}
		if err := identity.CheckCredentialAuthority(r, e, 7, now); err != nil {
			t.Fatal("valid owned reference denied", err)
		}
	}
	for _, version := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64} {
		r, e := base, expected
		r.User.Version, r.AuthorityVersion, e.Version = math.MaxUint64, version, version
		r.Credential = e
		if err := identity.CheckCredentialAuthority(r, e, version, now); err != nil {
			t.Fatal("full-width or independent aggregate rejected", err)
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := identity.CheckCredentialAuthority(base, expected, 7, now); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, base); got != "identity.CredentialAuthorityRecord(redacted)" {
			t.Fatal("metadata disclosed", got)
		}
	}
}

func TestCredentialAuthorityQuery(t *testing.T) {
	valid := identity.CredentialAuthorityQuery{TenantID: "tenant-a", UserID: "user-a", CredentialID: "credential-a"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "bad id", "bad\nvalue", strings.Repeat("x", 129), "\xff"} {
		for field := range 3 {
			q := valid
			switch field {
			case 0:
				q.TenantID = identity.TenantID(invalid)
			case 1:
				q.UserID = identity.UserID(invalid)
			case 2:
				q.CredentialID = identity.CredentialID(invalid)
			}
			var input identity.InvalidInputError
			if err := q.Validate(); !errors.As(err, &input) {
				t.Fatal("invalid scope admitted")
			}
		}
	}
}
