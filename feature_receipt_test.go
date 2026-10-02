package identity_test

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func featureResult() identity.CommandResult {
	return identity.CommandResult{Binding: featureBinding(), Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: featureOperation(), BeforeVersion: 0, AfterVersion: 1}}
}

func TestFeatureReceiptOutcomeAndVersionRules(t *testing.T) {
	r := featureResult()
	if err := r.Validate(); err != nil {
		t.Fatal("committed feature receipt", err)
	}
	r.Feature.BeforeVersion = math.MaxUint64 - 1
	r.Feature.AfterVersion = math.MaxUint64
	if err := r.Validate(); err != nil {
		t.Fatal("full-width successor", err)
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		r = featureResult()
		r.Outcome = outcome
		r.AuditEventID = ""
		r.Feature.BeforeVersion = 0
		r.Feature.AfterVersion = 0
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Minute
		}
		if err := r.Validate(); err != nil {
			t.Fatal("valid noncommitted feature", outcome, err)
		}
		r.Feature.AfterVersion = 1
		if err := r.Validate(); err == nil {
			t.Fatal("noncommitted successor admitted", outcome)
		}
	}
	r = featureResult()
	r.Feature.Operation.RecordRequirement = identity.FeatureRecordOmitted
	r.Binding.RecordID = ""
	r.Feature.AfterVersion = 0
	if err := r.Validate(); err != nil {
		t.Fatal("record-free result", err)
	}
	r.Feature.AfterVersion = 1
	if err := r.Validate(); err == nil {
		t.Fatal("invented record version")
	}
}

func TestFeatureReceiptRejectsMixedAndMismatchedState(t *testing.T) {
	for _, mutate := range []func(*identity.CommandResult){
		func(r *identity.CommandResult) { r.Feature = nil },
		func(r *identity.CommandResult) { r.Feature.Operation = identity.FeatureOperation{} },
		func(r *identity.CommandResult) { r.Feature.Operation.SchemaVersion++ },
		func(r *identity.CommandResult) { r.Binding.SchemaID = "other-schema" },
		func(r *identity.CommandResult) { r.Binding.RecordID = "" },
		func(r *identity.CommandResult) { r.Binding.LinkMode = 1 },
		func(r *identity.CommandResult) { r.Feature.BeforeVersion = math.MaxUint64; r.Feature.AfterVersion = 0 },
		func(r *identity.CommandResult) { r.Feature.AfterVersion = 2 },
		func(r *identity.CommandResult) { r.AuditEventID = "" },
		func(r *identity.CommandResult) {
			r.User = identity.User{ID: r.Binding.UserID, TenantID: r.Binding.TenantID, Status: identity.StatusActive, Version: 1}
		},
		func(r *identity.CommandResult) { r.ExpectedVersion = 1 },
		func(r *identity.CommandResult) { r.Profile = &identity.UserProfile{} },
		func(r *identity.CommandResult) { r.Revocation = &identity.RevocationOutcome{} },
		func(r *identity.CommandResult) { r.Unlink = &identity.AccountUnlinkReceipt{} },
		func(r *identity.CommandResult) { r.Link = &identity.AccountLinkReceipt{} },
		func(r *identity.CommandResult) { r.Identifier = &identity.IdentifierReceipt{} },
		func(r *identity.CommandResult) { r.Outcome = identity.CommitOutcomeInvalid },
		func(r *identity.CommandResult) { r.RetryAfter = time.Second },
	} {
		r := featureResult()
		mutate(&r)
		if r.Validate() == nil {
			t.Fatal("invalid or mixed feature receipt")
		}
	}
	r := featureResult()
	r.Binding.OperationID = "identity.user.create"
	r.Binding.RecordID = ""
	if r.Validate() == nil {
		t.Fatal("feature payload borrowed kernel binding")
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		r := featureResult()
		r.Outcome = outcome
		r.Feature.AfterVersion = 0
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Second
		}
		if r.Validate() == nil {
			t.Fatal("noncommitted feature leaked audit")
		}
		r.AuditEventID = ""
		r.RetryAfter = 0
		if (r.Validate() == nil) != (outcome != identity.CommitOutcomeInProgress) {
			t.Fatal("retry delay rule")
		}
		r.RetryAfter = time.Minute + time.Nanosecond
		if r.Validate() == nil {
			t.Fatal("unbounded or misplaced retry delay")
		}
	}
}

func TestFeatureReceiptHistoricalKernelJSONBytes(t *testing.T) {
	// Captured pre-extension canonical kernel shape, including existing nil keys.
	const historical = `{"Binding":{"CommandID":"AAAAAAAAAAAAAAAAAAAAAQ","TenantID":"tenant","UserID":"user","ActorID":"actor","ActorKind":"user","OperationID":"identity.user.create","PolicyID":"policy","PolicyVersion":1,"SchemaID":"profile","SchemaVersion":1,"CorrelationID":"correlation","RecordID":"","LinkMode":0},"Outcome":2,"User":{"ID":"user","TenantID":"tenant","Status":"active","Version":1},"AuditEventID":"audit","RetryAfter":0,"ExpectedVersion":0,"Profile":null,"Revocation":null,"Unlink":null,"Link":null,"Identifier":null}`
	var r identity.CommandResult
	if err := json.Unmarshal([]byte(historical), &r); err != nil || r.Validate() != nil {
		t.Fatal("historical receipt invalid", err)
	}
	b, err := json.Marshal(r)
	if err != nil || string(b) != historical {
		t.Fatal("kernel canonical bytes changed")
	}
	r.Feature = &identity.FeatureReceipt{Operation: featureOperation()}
	if r.Validate() == nil {
		t.Fatal("kernel receipt accepted feature contamination")
	}
}

func TestFeatureReceiptJSONPreservesExactSafeProjection(t *testing.T) {
	r := featureResult()
	r.Feature.BeforeVersion = math.MaxUint64 - 1
	r.Feature.AfterVersion = math.MaxUint64
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got identity.CommandResult
	if err = json.Unmarshal(b, &got); err != nil || got.Validate() != nil {
		t.Fatal("feature receipt roundtrip", err)
	}
	if got.Feature == nil || got.Feature.Operation != featureOperation() || got.Binding != featureBinding() || got.Feature.BeforeVersion != math.MaxUint64-1 || got.Feature.AfterVersion != math.MaxUint64 || got.AuditEventID != "audit-a" {
		t.Fatal("safe feature projection changed")
	}
	if r.Feature.BeforeVersion != math.MaxUint64-1 || r.Feature.AfterVersion != math.MaxUint64 {
		t.Fatal("encoding mutated input")
	}
}

func FuzzFeatureReceiptVersions(f *testing.F) {
	f.Add(uint64(0), uint64(1), uint8(identity.CommitOutcomeCommitted), int64(0))
	f.Add(uint64(math.MaxUint64-1), uint64(math.MaxUint64), uint8(identity.CommitOutcomeCommitted), int64(0))
	f.Add(uint64(0), uint64(0), uint8(identity.CommitOutcomeInProgress), int64(time.Second))
	f.Fuzz(func(t *testing.T, before, after uint64, outcome uint8, retry int64) {
		r := featureResult()
		r.Feature.BeforeVersion = before
		r.Feature.AfterVersion = after
		r.Outcome = identity.CommitOutcome(outcome)
		r.RetryAfter = time.Duration(retry)
		if r.Outcome != identity.CommitOutcomeCommitted {
			r.AuditEventID = ""
		}
		valid := false
		switch r.Outcome {
		case identity.CommitOutcomeCommitted:
			valid = before != math.MaxUint64 && after > 0 && after-before == 1 && retry == 0
		case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict:
			valid = before == 0 && after == 0 && retry == 0
		case identity.CommitOutcomeInProgress:
			valid = before == 0 && after == 0 && retry > 0 && retry <= int64(time.Minute)
		}
		if (r.Validate() == nil) != valid {
			t.Fatal("outcome/version oracle disagreement")
		}
	})
}
