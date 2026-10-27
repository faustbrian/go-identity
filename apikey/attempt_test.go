package apikey_test

import (
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
