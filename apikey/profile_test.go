package apikey_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func configuration(t *testing.T) apikey.Configuration {
	t.Helper()
	c, err := apikey.NewConfiguration(apikey.ConfigurationSpec{
		ID: "automation", Revision: 1, State: apikey.ConfigurationActive,
		Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api",
		PermissionReduction: apikey.PermissionReductionNarrow,
		MaximumLifetime:     90 * 24 * time.Hour, MaximumRead: time.Second,
		ClockUncertainty: time.Second, DecisionRaceBudget: time.Second,
		Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestModernSecretIsOneRevealAndBoundToStoredConfiguration(t *testing.T) {
	c := configuration(t)
	pepper, err := apikey.NewPepper(1, []byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := apikey.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := s.Digest(pepper, "tenant-a", c)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%+v %#v", s, pepper); strings.Contains(got, "pppp") {
		t.Fatal("pepper exposed")
	}
	if _, err := json.Marshal(s); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatalf("secret JSON: %v", err)
	}
	var winners atomic.Int32
	var wire string
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			if raw, err := s.Reveal(); err == nil {
				wire = raw
				winners.Add(1)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 || !strings.HasPrefix(wire, "idk_") || len(wire) != 47 {
		t.Fatal("not one modern reveal")
	}
	presented, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := presented.Digest(pepper, "tenant-a", c)
	if err != nil || !digest.Equal(got) {
		t.Fatal("revealed secret no longer verifies")
	}
	other, _ := presented.Digest(pepper, "tenant-b", c)
	if digest.Equal(other) {
		t.Fatal("tenant substitution")
	}
	otherPepper, _ := apikey.NewPepper(2, []byte(strings.Repeat("p", 32)))
	other, _ = presented.Digest(otherPepper, "tenant-a", c)
	if digest.Equal(other) {
		t.Fatal("pepper revision substitution")
	}
	for _, bad := range []string{"", wire + "=", "x" + wire, wire[:46], "idk_" + strings.Repeat("A", 42) + "B"} {
		if _, err := apikey.ParseSecret(bad); err == nil {
			t.Fatal("accepted malformed secret")
		}
	}
}

func TestOwnerScopeReductionAndOriginalFreshnessNeverExpandAuthority(t *testing.T) {
	c := configuration(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	record := apikey.Record{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Owner: owner, Version: 4, AuthorityVersion: 7,
		ConfigurationID: "automation", ConfigurationRevision: 1, Status: apikey.KeyActive,
		Grant: []string{"invoice.read", "invoice.write"}, CreatedAt: start.Add(-time.Hour), ExpiresAt: start.Add(time.Hour),
		RootID: "AQEBAQEBAQEBAQEBAQEBAQ", RootVersion: 7, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api"}
	current := apikey.CurrentAuthority{Owner: owner, OwnerActive: true, TenantActive: true,
		Permissions: []string{"invoice.read", "profile.read"}, PolicyVersion: 8,
		ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: "automation", Version: 10},
		ReadStartedAt:          start, VerifiedAt: start.Add(time.Second), ValidUntil: start.Add(20 * time.Second)}
	policy := apikey.ScopePolicy{}
	got, err := policy.EffectiveGrant(record, current, c, start.Add(2*time.Second))
	if err != nil || len(got) != 1 || got[0] != "invoice.read" {
		t.Fatalf("grant: %v %v", got, err)
	}
	attempt, _ := apikey.ParseVerificationAttemptID("AgICAgICAgICAgICAgICAg")
	known := apikey.AtomicVerificationResult{AttemptID: attempt, Fingerprint: [32]byte{1}, Original: identity.RecoveryQuery{CommandID: identity.CommandID(attempt), TenantID: "tenant-a", UserID: "user-a", ActorID: identity.ActorID(record.ID), ActorKind: authorization.SubjectAPIKey, OperationID: "identity.apikey.verify"}, State: apikey.VerificationAttemptNotApplicable, Outcome: identity.CommitOutcomeCommitted, Result: &apikey.VerificationResult{Record: record, Owner: owner, Grant: got, PolicyVersion: current.PolicyVersion, ConfigurationAuthority: current.ConfigurationAuthority, ReadStartedAt: current.ReadStartedAt, VerifiedAt: current.VerifiedAt, ValidUntil: current.ValidUntil}}
	if known.Validate() != nil || known.Result.ValidateAt(c, start.Add(2*time.Second)) != nil {
		t.Fatal("known unlimited result rejected")
	}
	t.Run("recorded-result-original-freshness", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			now    time.Time
			change func(*apikey.VerificationResult)
		}{
			{"exact-deadline", start.Add(20 * time.Second), func(*apikey.VerificationResult) {}},
			{"after-deadline", start.Add(21 * time.Second), func(*apikey.VerificationResult) {}},
			{"excessive-source-lease", start.Add(2 * time.Second), func(r *apikey.VerificationResult) { r.ValidUntil = start.Add(21 * time.Second) }},
			{"future-verified", start.Add(500 * time.Millisecond), func(r *apikey.VerificationResult) { r.VerifiedAt = start.Add(750 * time.Millisecond) }},
		} {
			t.Run(test.name, func(t *testing.T) {
				copy := *known.Result
				test.change(&copy)
				if !errors.Is(copy.ValidateAt(c, test.now), apikey.ErrDenied) {
					t.Fatal("recorded result accepted invalid original freshness")
				}
			})
		}
		copy := *known.Result
		if copy.ValidateAt(c, start.Add(19*time.Second)) != nil {
			t.Fatal("still-valid original result rejected")
		}
		if !copy.ValidUntil.Equal(start.Add(20*time.Second)) || !errors.Is(copy.ValidateAt(c, start.Add(20*time.Second)), apikey.ErrDenied) {
			t.Fatal("reuse reset the original freshness deadline")
		}
	})
	known.Result.Grant = []string{"profile.read"}
	if known.Validate() == nil {
		t.Fatal("known result expanded immutable grant")
	}
	if _, err := policy.Authorize(record, current, c, []string{"invoice.write"}, start.Add(2*time.Second)); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("removed permission authorized before persistence")
	}
	id, _ := identity.ParseCommandID("AgICAgICAgICAgICAgICAg")
	d, err := policy.DecidePermissionReduction(id, record, current, c, start.Add(2*time.Second))
	if err != nil || d.Disposition != apikey.PermissionReductionNarrow || len(d.Grant) != 1 || d.ExpectedKeyVersion != 4 || d.Owner.Version() != 3 || d.PolicyVersion != 8 {
		t.Fatalf("reduction: %v %v", d, err)
	}
	t.Run("committed-reduction-exact-transition", func(t *testing.T) {
		next := record
		next.Version = d.ExpectedKeyVersion + 1
		next.AuthorityVersion = d.ExpectedAuthorityVersion + 1
		next.RootVersion = next.AuthorityVersion
		next.Owner = d.Owner
		next.Grant = append([]string(nil), d.Grant...)
		result := apikey.PermissionReductionResult{Decision: d, Outcome: identity.CommitOutcomeCommitted, Record: &next}
		postConfiguration := d.ConfigurationAuthority
		postConfiguration.Version++
		result.ConfigurationAuthority = &postConfiguration
		if result.Validate(c) != nil {
			t.Fatal("valid committed Narrow transition rejected")
		}
		for name, change := range map[string]func(*apikey.ConfigurationAuthorityBinding){
			"tenant":        func(b *apikey.ConfigurationAuthorityBinding) { b.TenantID = "other" },
			"configuration": func(b *apikey.ConfigurationAuthorityBinding) { b.ConfigurationID = "other" },
			"zero":          func(b *apikey.ConfigurationAuthorityBinding) { b.Version = 0 },
			"not-successor": func(b *apikey.ConfigurationAuthorityBinding) { b.Version-- },
		} {
			t.Run("configuration-"+name, func(t *testing.T) {
				copy := postConfiguration
				change(&copy)
				candidate := result
				candidate.ConfigurationAuthority = &copy
				if candidate.Validate(c) == nil {
					t.Fatal("committed result accepted wrong shared configuration authority")
				}
			})
		}
		unknown := result
		unknown.Outcome = identity.CommitOutcomeUnknown
		unknown.Record = nil
		if unknown.Validate(c) == nil {
			t.Fatal("unknown result invented post-configuration state")
		}
		unknown.ConfigurationAuthority = nil
		if unknown.Validate(c) != nil {
			t.Fatal("unknown exact decision without post-state rejected")
		}

		// A different root shares the configuration authority, not the mutated
		// credential epoch. Its original grant needs no reduction.
		second := record
		second.ID = "key-b"
		second.RootID = second.ID
		second.Version = 9
		second.AuthorityVersion = 23
		second.RootVersion = 23
		second.Grant = []string{"invoice.read"}
		secondCurrent := current
		secondCurrent.ConfigurationAuthority = postConfiguration
		secondCurrent.ReadStartedAt = start.Add(3 * time.Second)
		secondCurrent.VerifiedAt = start.Add(3500 * time.Millisecond)
		secondCurrent.ValidUntil = start.Add(23 * time.Second)
		secondGrant, e := policy.Authorize(second, secondCurrent, c, []string{"invoice.read"}, start.Add(4*time.Second))
		if e != nil {
			t.Fatal("shared configuration advance revoked independent root")
		}
		secondResult := apikey.VerificationResult{Record: second, Owner: owner, Grant: secondGrant, PolicyVersion: current.PolicyVersion, ConfigurationAuthority: postConfiguration, ReadStartedAt: secondCurrent.ReadStartedAt, VerifiedAt: secondCurrent.VerifiedAt, ValidUntil: secondCurrent.ValidUntil}
		if secondResult.ValidateAt(c, start.Add(4*time.Second)) != nil || secondResult.Record.Version != 9 || secondResult.Record.RootVersion != 23 || secondResult.Record.AuthorityVersion != 23 || secondResult.ConfigurationAuthority.Version != 11 {
			t.Fatal("independent credential root conflated with shared configuration authority")
		}
		if _, e := policy.DecidePermissionReduction(id, second, secondCurrent, c, start.Add(4*time.Second)); !errors.Is(e, apikey.ErrNoReduction) {
			t.Fatal("unaffected second key required a credential rewrite")
		}
		for name, change := range map[string]func(*apikey.Record){
			"different-owner":   func(r *apikey.Record) { s := r.Owner.Spec(); s.UserID = "other"; r.Owner, _ = apikey.NewOwner(s) },
			"owner-epoch":       func(r *apikey.Record) { s := r.Owner.Spec(); s.Version++; r.Owner, _ = apikey.NewOwner(s) },
			"different-key":     func(r *apikey.Record) { r.ID = "different-key"; r.RootID = r.ID },
			"key-version":       func(r *apikey.Record) { r.Version++ },
			"authority-version": func(r *apikey.Record) { r.AuthorityVersion++; r.RootVersion = r.AuthorityVersion },
			"grant":             func(r *apikey.Record) { r.Grant = []string{"invoice.read", "invoice.write"} },
			"status":            func(r *apikey.Record) { r.Status = apikey.KeyRevoked },
		} {
			t.Run(name, func(t *testing.T) {
				copy := next
				copy.Grant = append([]string(nil), next.Grant...)
				change(&copy)
				if copy.Validate(c) != nil {
					t.Fatal("case failed before exact committed-transition comparison")
				}
				candidate := result
				candidate.Record = &copy
				if candidate.Validate(c) == nil {
					t.Fatal("committed reduction accepted mismatched transition")
				}
			})
		}
	})
	for name, change := range map[string]func(*apikey.ConfigurationAuthorityBinding){
		"tenant":        func(b *apikey.ConfigurationAuthorityBinding) { b.TenantID = "other" },
		"configuration": func(b *apikey.ConfigurationAuthorityBinding) { b.ConfigurationID = "other" },
		"zero":          func(b *apikey.ConfigurationAuthorityBinding) { b.Version = 0 },
	} {
		t.Run("current-configuration-"+name, func(t *testing.T) {
			copy := current
			change(&copy.ConfigurationAuthority)
			if _, err := policy.EffectiveGrant(record, copy, c, start.Add(2*time.Second)); !errors.Is(err, apikey.ErrDenied) {
				t.Fatal("current authority accepted missing or foreign configuration binding")
			}
			result := *known.Result
			result.Grant = got
			result.ConfigurationAuthority = copy.ConfigurationAuthority
			if !errors.Is(result.ValidateAt(c, start.Add(2*time.Second)), apikey.ErrDenied) {
				t.Fatal("recorded authority accepted missing or foreign configuration binding")
			}
		})
	}
	d.Grant = append(d.Grant, "invoice.write")
	if d.Validate() == nil {
		t.Fatal("non-strict narrowing accepted")
	}
	current.ValidUntil = start.Add(21 * time.Second)
	if _, err := policy.EffectiveGrant(record, current, c, start.Add(2*time.Second)); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("renewed source lease accepted")
	}
	current.ValidUntil = start.Add(20 * time.Second)
	if _, err := policy.EffectiveGrant(record, current, c, start.Add(20*time.Second)); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("expired source lease accepted")
	}
	current.OwnerActive = false
	if _, err := policy.EffectiveGrant(record, current, c, start.Add(2*time.Second)); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("suspended owner accepted")
	}
	for _, s := range []apikey.OwnerSpec{{TenantID: "tenant-a", UserID: "user-a", Version: 1}, {TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", OrganizationID: "org-a", Version: 1}, {TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a"}} {
		if _, err := apikey.NewOwner(s); err == nil {
			t.Fatal("invalid tagged owner accepted")
		}
	}
}
