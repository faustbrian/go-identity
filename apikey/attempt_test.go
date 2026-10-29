package apikey_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestUnlimitedAttemptCannotPretendDebitOrSuccessWithoutExactKnownResult(t *testing.T) {
	id, err := apikey.ParseVerificationAttemptID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apikey.ParseVerificationAttemptID(""); err == nil {
		t.Fatal("zero attempt")
	}
	r := apikey.AtomicVerificationResult{AttemptID: id, State: apikey.VerificationAttemptNotDebited, Outcome: identity.CommitOutcomeNotCommitted}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Result = &apikey.VerificationResult{}
	if r.Validate() == nil {
		t.Fatal("denial carried principal")
	}
	r.Result = nil
	r.State, r.Outcome = apikey.VerificationAttemptNotApplicable, identity.CommitOutcomeCommitted
	if r.Validate() == nil {
		t.Fatal("success absent exact principal")
	}
	original := identity.RecoveryQuery{CommandID: identity.CommandID(id), TenantID: "tenant-a", UserID: "user-a", ActorKind: authorization.SubjectAPIKey, ActorID: "key-a", OperationID: "identity.apikey.verify"}
	r.Fingerprint = [32]byte{1}
	r.Original = original
	r.State, r.Outcome = apikey.VerificationAttemptPossibleDebit, identity.CommitOutcomeUnknown
	if r.Validate() != nil {
		t.Fatal("unknown debit cannot be represented")
	}
	r.Result = &apikey.VerificationResult{}
	if r.Validate() == nil {
		t.Fatal("unknown debit carried principal")
	}
	query := apikey.VerificationReconcileQuery{AttemptID: id, TenantID: "tenant-a", Fingerprint: [32]byte{1}, Original: original}
	if query.Validate() != nil {
		t.Fatal("exact status query rejected")
	}
	query.Fingerprint = [32]byte{}
	if query.Validate() == nil {
		t.Fatal("unbound status query accepted")
	}
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
	decision := apikey.PermissionReductionDecision{CommandID: identity.CommandID(id), KeyID: "original", Owner: owner, ExpectedKeyVersion: 1, ExpectedAuthorityVersion: 1, PolicyVersion: 1, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: "automation", Version: 1}, PriorGrant: []string{"read", "write"}, EffectiveCurrentGrant: []string{"read"}, Grant: []string{"read"}, Disposition: apikey.PermissionReductionNarrow}
	reduction := apikey.PermissionReductionResult{Decision: decision, Outcome: identity.CommitOutcomeUnknown, Record: &apikey.Record{}}
	if reduction.Validate(configuration(t)) == nil {
		t.Fatal("unknown reduction carried authoritative record")
	}
}

func TestVerificationReconciliationPreservesExactOriginalNamespace(t *testing.T) {
	id, _ := apikey.ParseVerificationAttemptID("AQEBAQEBAQEBAQEBAQEBAQ")
	original := identity.RecoveryQuery{CommandID: identity.CommandID(id), TenantID: "tenant-a", UserID: "user-a", ActorKind: authorization.SubjectAPIKey, ActorID: "key-a", OperationID: "identity.apikey.verify"}
	query := apikey.VerificationReconcileQuery{AttemptID: id, TenantID: "tenant-a", Fingerprint: [32]byte{1}, Original: original}
	if query.Validate() != nil {
		t.Fatal("known original scope rejected")
	}
	for _, change := range []func(*apikey.VerificationReconcileQuery){
		func(q *apikey.VerificationReconcileQuery) { q.Original.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(q *apikey.VerificationReconcileQuery) { q.Original.TenantID = "other" },
		func(q *apikey.VerificationReconcileQuery) { q.Original.OperationID = "identity.apikey.create" },
		func(q *apikey.VerificationReconcileQuery) { q.Original.ActorKind = authorization.SubjectUser },
		func(q *apikey.VerificationReconcileQuery) { q.Original.AnonymousFlowID = string(id) },
	} {
		bad := query
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("changed original scope admitted")
		}
	}
	query.Original.UserID = ""
	query.Original.AnonymousFlowID = string(id)
	query.Original.ActorID = "api-key-verifier"
	query.Original.ActorKind = authorization.SubjectServiceAccount
	if query.Validate() != nil {
		t.Fatal("original anonymous denial namespace rejected")
	}
	result := apikey.AtomicVerificationResult{AttemptID: id, Fingerprint: query.Fingerprint, Original: query.Original, State: apikey.VerificationAttemptNotDebited, Outcome: identity.CommitOutcomeCommitted}
	if result.Validate() != nil {
		t.Fatal("known denial lost original inquiry")
	}
	result.Original.CommandID = "AgICAgICAgICAgICAgICAg"
	if result.Validate() == nil {
		t.Fatal("result correlation changed original attempt")
	}
}

func organizationVerificationResult(t *testing.T) (apikey.AtomicVerificationResult, apikey.Configuration, time.Time) {
	t.Helper()
	c := configuration(t)
	id, _ := apikey.ParseVerificationAttemptID("AgICAgICAgICAgICAgICAg")
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 4})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	record := apikey.Record{ID: "key-a", Owner: owner, Version: 8, AuthorityVersion: 6, RootID: "key-a", RootVersion: 6,
		ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Status: apikey.KeyActive,
		Grant: []string{"invoice.read"}, CreatedAt: start.Add(-time.Hour), ExpiresAt: start.Add(time.Hour),
		Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	r := apikey.AtomicVerificationResult{AttemptID: id, Fingerprint: [32]byte{1},
		Original: identity.RecoveryQuery{CommandID: identity.CommandID(id), TenantID: "tenant-a", AnonymousFlowID: string(id), ActorKind: authorization.SubjectAPIKey, ActorID: "key-a", OperationID: "identity.apikey.verify"},
		State:    apikey.VerificationAttemptNotApplicable, Outcome: identity.CommitOutcomeCommitted,
		Result: &apikey.VerificationResult{Record: record, Owner: owner, Grant: []string{"invoice.read"}, PolicyVersion: 3,
			ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: c.Spec().ID, Version: 2},
			ReadStartedAt:          start, VerifiedAt: start.Add(time.Second), ValidUntil: start.Add(20 * time.Second)}}
	return r, c, start
}

func TestOrganizationVerificationPreservesKnownNonhumanScope(t *testing.T) {
	r, c, start := organizationVerificationResult(t)
	if err := r.Validate(); err != nil {
		t.Fatalf("known organization credential without fabricated human rejected: %v", err)
	}
	q := apikey.VerificationReconcileQuery{AttemptID: r.AttemptID, TenantID: r.Original.TenantID, Fingerprint: r.Fingerprint, Original: r.Original}
	if err := q.Validate(); err != nil {
		t.Fatalf("exact known nonhuman inquiry rejected: %v", err)
	}
	if r.Result.ValidateAt(c, start.Add(2*time.Second)) != nil || r.Result.ValidateAt(c, start.Add(20*time.Second)) == nil {
		t.Fatal("organization result did not preserve original evidence deadline")
	}
	for _, test := range []struct {
		name   string
		change func(*apikey.AtomicVerificationResult)
	}{
		{"fabricated-human", func(r *apikey.AtomicVerificationResult) { r.Original.UserID = "creator-a" }},
		{"missing-anonymous-namespace", func(r *apikey.AtomicVerificationResult) { r.Original.AnonymousFlowID = "" }},
		{"other-attempt-namespace", func(r *apikey.AtomicVerificationResult) { r.Original.AnonymousFlowID = "AQEBAQEBAQEBAQEBAQEBAQ" }},
		{"unknown-service-actor", func(r *apikey.AtomicVerificationResult) { r.Original.ActorKind = authorization.SubjectServiceAccount }},
		{"other-key-actor", func(r *apikey.AtomicVerificationResult) { r.Original.ActorID = "key-b" }},
		{"other-record", func(r *apikey.AtomicVerificationResult) { r.Original.RecordID = "key-b" }},
		{"other-tenant", func(r *apikey.AtomicVerificationResult) { r.Original.TenantID = "tenant-b" }},
		{"user-owner-with-nonhuman-routing", func(r *apikey.AtomicVerificationResult) {
			o, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 4})
			r.Result.Owner, r.Result.Record.Owner = o, o
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := r
			copy := *r.Result
			bad.Result = &copy
			test.change(&bad)
			if bad.Validate() == nil {
				t.Fatal("nonhuman result accepted mismatched original authority")
			}
		})
	}
	q.Original.RecordID = string(q.Original.ActorID)
	if q.Validate() != nil {
		t.Fatal("exact optional record binding rejected")
	}
}

func TestOrganizationTerminalCredentialEpochIsExactWhileUserPolicyEpochMayAdvance(t *testing.T) {
	for _, kind := range []apikey.OwnerKind{apikey.OwnerUser, apikey.OwnerOrganization} {
		for _, currentVersion := range []uint64{3, 4, 5} {
			t.Run(fmt.Sprintf("owner-%d/current-%d", kind, currentVersion), func(t *testing.T) {
				r, c, start := organizationVerificationResult(t)
				spec := r.Result.Record.Owner.Spec()
				if kind == apikey.OwnerUser {
					spec.Kind, spec.UserID, spec.OrganizationID = apikey.OwnerUser, "user-a", ""
					r.Original.UserID, r.Original.AnonymousFlowID = "user-a", ""
				}
				recordedOwner, err := apikey.NewOwner(spec)
				if err != nil {
					t.Fatal(err)
				}
				spec.Version = currentVersion
				currentOwner, err := apikey.NewOwner(spec)
				if err != nil {
					t.Fatal(err)
				}
				r.Result.Record.Owner, r.Result.Owner = recordedOwner, currentOwner
				current := apikey.CurrentAuthority{Owner: currentOwner, OwnerActive: true, TenantActive: true, Permissions: []string{"invoice.read"}, PolicyVersion: r.Result.PolicyVersion,
					ConfigurationAuthority: r.Result.ConfigurationAuthority, ReadStartedAt: r.Result.ReadStartedAt, VerifiedAt: r.Result.VerifiedAt, ValidUntil: r.Result.ValidUntil}
				want := currentVersion == 4 || kind == apikey.OwnerUser && currentVersion > 4
				if got := r.Validate() == nil; got != want {
					t.Errorf("atomic result accepted=%v, want %v", got, want)
				}
				if got := r.Result.ValidateAt(c, start.Add(2*time.Second)) == nil; got != want {
					t.Errorf("fresh result accepted=%v, want %v", got, want)
				}
				grant, err := (apikey.ScopePolicy{}).EffectiveGrant(r.Result.Record, current, c, start.Add(2*time.Second))
				if got := err == nil; got != want || want && (len(grant) != 1 || grant[0] != "invoice.read") {
					t.Errorf("effective grant=%v accepted=%v, want acceptance %v", grant, got, want)
				}
			})
		}
	}
}

func TestConfigurationRejectsUnsupportedOrUnboundedProfiles(t *testing.T) {
	c := configuration(t)
	spec := c.Spec()
	for _, change := range []func(*apikey.ConfigurationSpec){
		func(s *apikey.ConfigurationSpec) { s.PermissionReduction = apikey.PermissionReductionUnspecified },
		func(s *apikey.ConfigurationSpec) { s.MaximumRead = 11 * time.Second },
		func(s *apikey.ConfigurationSpec) {
			s.ClockUncertainty = 9 * time.Second
			s.DecisionRaceBudget = 2 * time.Second
		},
		func(s *apikey.ConfigurationSpec) { s.Quota = apikey.QuotaUnspecified },
		func(s *apikey.ConfigurationSpec) { s.Cache = apikey.CacheUnspecified },
		func(s *apikey.ConfigurationSpec) { s.Revision = 0 },
	} {
		bad := spec
		change(&bad)
		if _, err := apikey.NewConfiguration(bad); err == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
	if c.Spec() != spec {
		t.Fatal("constructor did not freeze configuration")
	}
}
