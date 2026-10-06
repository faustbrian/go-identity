package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// Native feature observations retain only schema/scope metadata. No current
// registry is needed to read immutable history, and no history grants execution.
func TestFeatureCommandObservationPreservesExactHistoricalProfile(t *testing.T) {
	for _, state := range []string{"pending", "committed", "aborted"} {
		c, command, p := featurePlanFixture(t)
		spec, _ := command.Feature()
		claim, err := prepareClaim(command, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := claimFingerprint([32]byte{1}, claim.canonical)
		wire, err := encodeFeaturePlan(spec.Binding, fingerprint, p)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		until := now.Add(time.Second)
		stored := commandObservation{tenant: string(spec.Binding.TenantID), purpose: spec.Binding.OperationID, scope: claim.safeFields, state: &state, now: now, until: &until, plan: wire, fingerprint: bytes.Clone(fingerprint[:])}
		expected := identity.CommitOutcomeInProgress
		if state != "pending" {
			expected = identity.CommitOutcomeCommitted
			class := "committed"
			receipt := identity.CommandResult{Binding: spec.Binding, Outcome: expected, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: spec.Operation, AfterVersion: 1}}
			if state == "aborted" {
				expected, class = identity.CommitOutcomeNotCommitted, "denied"
				receipt.Outcome, receipt.AuditEventID, receipt.Feature.AfterVersion = expected, "", 0
			}
			stored.result, err = encodeJournalResult(claim, receipt)
			if err != nil {
				t.Fatal(err)
			}
			version := int32(1)
			stored.resultVersion, stored.class = &version, &class
		}
		q, caller := queryInputs(spec.Binding)
		var reads, decisions int
		c.registry = nil // Historical observation must not use today's composition.
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			decisions++
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { reads++; return stored, nil }
		got, err := c.QueryCommand(context.Background(), q, caller)
		var forbidden identity.ForbiddenError
		if state == "aborted" && !errors.As(err, &forbidden) || state != "aborted" && err != nil || got.Outcome != expected || got.Binding != spec.Binding || got.Feature == nil || *got.Feature != spec.Operation || got.Validate() != nil {
			t.Fatalf("%s historical feature observation lost: %v", state, err)
		}
		if reads != 1 || decisions != 1 {
			t.Fatal("observation skipped policy/read")
		}
		if state != "pending" {
			full, fullErr := c.RecoverFeatureCommand(context.Background(), q, caller)
			if full.Outcome != expected || full.Feature == nil || full.Feature.Operation != spec.Operation || full.Validate() != nil || state == "committed" && (fullErr != nil || full.AuditEventID != "audit-a" || full.Feature.AfterVersion != 1) || state == "aborted" && !errors.As(fullErr, &forbidden) {
				t.Fatal("exact terminal feature receipt lost", fullErr)
			}
			full.Feature.Operation.SchemaVersion++
			full, _ = c.RecoverFeatureCommand(context.Background(), q, caller)
			if full.Feature == nil || full.Feature.Operation != spec.Operation {
				t.Fatal("full receipt mutated history")
			}
		}
		got.Feature.SchemaVersion++
		again, _ := c.QueryCommand(context.Background(), q, caller)
		if again.Feature == nil || *again.Feature != spec.Operation {
			t.Fatal("public result altered history")
		}
		changed := q
		changed.RecordID = "other"
		beforeReads, beforeDecisions := reads, decisions
		bad, err := c.QueryCommand(context.Background(), changed, callerForQuery(caller, changed))
		if !errors.As(err, &forbidden) || bad != (CommandRecord{}) || reads != beforeReads+1 || decisions != beforeDecisions+1 {
			t.Fatal("wrong feature scope disclosed result or changed read shape")
		}
		beforeReads, beforeDecisions = reads, decisions
		full, fullErr := c.RecoverFeatureCommand(context.Background(), changed, callerForQuery(caller, changed))
		if !errors.As(fullErr, &forbidden) || full.Feature != nil || full.Binding.CommandID != "" || reads != beforeReads+1 || decisions != beforeDecisions+1 {
			t.Fatal("full receipt changed wrong-scope read shape", fullErr)
		}
		for _, policyFailure := range []string{"denied", "error", "panic"} {
			c.queryPolicy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				decisions++
				if policyFailure == "panic" {
					panic("private-policy-diagnostic")
				}
				if policyFailure == "error" {
					return authorization.Decision{}, errors.New("private-policy-diagnostic")
				}
				return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
			})
			beforeReads, beforeDecisions = reads, decisions
			full, fullErr := c.RecoverFeatureCommand(context.Background(), q, caller)
			var unavailable identity.UnavailableError
			if full.Feature != nil || full.Binding.CommandID != "" || reads != beforeReads+1 || decisions != beforeDecisions+1 || policyFailure == "denied" && !errors.As(fullErr, &forbidden) || policyFailure != "denied" && !errors.As(fullErr, &unavailable) {
				t.Fatal("full receipt disclosed after failed current policy", policyFailure, fullErr)
			}
		}
	}
}

func TestFeatureScopeRejectsAlteredOwnerPolicyAndNoncanonicalBytes(t *testing.T) {
	s := featureCodecSpec()
	good := commandSafeFields(s.Binding, &s.Operation)
	b, feature, err := decodeObservedScope(good)
	if err != nil || b != s.Binding || feature == nil || *feature != s.Operation {
		t.Fatal("feature scope not reconstructed", err)
	}
	for _, wire := range [][]byte{
		append(bytes.Clone(good), 0),
		bytes.Replace(good, cborText("identity/session"), cborText("identity//session"), 1),
		bytes.Replace(good, append(cborText("record_requirement"), cborUint(2)...), append(cborText("record_requirement"), cborUint(256)...), 1),
		bytes.Replace(good, cborText("feature_owner"), cborText("unknown_owner"), 1),
	} {
		got, op, err := decodeObservedScope(wire)
		if err == nil || got != (identity.CommandBinding{}) || op != nil {
			t.Fatal("invalid feature scope escaped")
		}
	}
	// Legacy decoder's contract remains kernel-only.
	if _, err := decodeCommandScope(good); err == nil {
		t.Fatal("legacy decoder accepted feature scope")
	}
}

func TestFeatureObservationRejectsScopePlanAndReceiptSubstitution(t *testing.T) {
	c, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := claimFingerprint([32]byte{1}, claim.canonical)
	wire, err := encodeFeaturePlan(spec.Binding, fingerprint, plan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, class, version := "committed", "committed", int32(1)
	body, err := encodeJournalResult(claim, identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: spec.Operation, AfterVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	good := commandObservation{tenant: string(spec.Binding.TenantID), purpose: spec.Binding.OperationID, scope: claim.safeFields, state: &state, now: now, until: &now, plan: wire, fingerprint: bytes.Clone(fingerprint[:]), result: body, class: &class, resultVersion: &version}
	q, caller := queryInputs(spec.Binding)
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	for _, mutate := range []func(*commandObservation){
		func(o *commandObservation) {
			o.scope = bytes.Replace(o.scope, cborText("identity/session"), cborText("identity/password"), 1)
		},
		func(o *commandObservation) {
			o.plan = bytes.Replace(o.plan, cborText("identity/session"), cborText("identity/password"), 1)
		},
		func(o *commandObservation) { o.plan = queryFrozenPlan(t, codecBinding()) },
		func(o *commandObservation) {
			o.result = bytes.Replace(o.result, []byte("identity/session"), []byte("identity/password"), 1)
		},
		func(o *commandObservation) {
			o.result = bytes.Replace(o.result, []byte(`"AfterVersion":1`), []byte(`"AfterVersion":2`), 1)
		},
		func(o *commandObservation) {
			o.result = bytes.Replace(o.result, []byte(`"BeforeVersion":0`), []byte(`"BeforeVersion":1`), 1)
			o.result = bytes.Replace(o.result, []byte(`"AfterVersion":1`), []byte(`"AfterVersion":2`), 1)
		},
		func(o *commandObservation) { o.fingerprint = queryFingerprint() },
		func(o *commandObservation) { o.plan = append(bytes.Clone(o.plan), 0) },
	} {
		bad := good
		mutate(&bad)
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return bad, nil }
		got, err := c.QueryCommand(context.Background(), q, caller)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || got != (CommandRecord{}) {
			t.Fatal("substituted historical feature was disclosed")
		}
		if full, err := c.RecoverFeatureCommand(context.Background(), q, caller); !errors.As(err, &unavailable) || full.Feature != nil || full.Binding.CommandID != "" {
			t.Fatal("full receipt disclosed substituted history", err)
		}
	}
}

func TestFeatureCommandRecordValidation(t *testing.T) {
	s := featureCodecSpec()
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeInProgress} {
		operation := s.Operation
		r := CommandRecord{Binding: s.Binding, Outcome: outcome, Feature: &operation}
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Microsecond
		}
		if r.Validate() != nil {
			t.Fatal("valid historical record denied")
		}
		operation.SchemaVersion++
		if r.Validate() == nil {
			t.Fatal("mismatched feature record admitted")
		}
	}
	if (CommandRecord{}).Validate() == nil {
		t.Fatal("zero record admitted")
	}
}

func FuzzObservedCommandScope(f *testing.F) {
	s := featureCodecSpec()
	f.Add(commandSafeFields(s.Binding, &s.Operation))
	f.Add(commandSafeFields(codecBinding(), nil))
	f.Add([]byte{0xbf})
	f.Fuzz(func(t *testing.T, b []byte) {
		binding, feature, err := decodeObservedScope(b)
		if err != nil {
			return
		}
		if !bytes.Equal(b, commandSafeFields(binding, feature)) {
			t.Fatal("accepted noncanonical historical scope")
		}
		if feature != nil && binding.ValidateFor(*feature) != nil {
			t.Fatal("accepted malformed feature scope")
		}
	})
}
