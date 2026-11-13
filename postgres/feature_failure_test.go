package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func featureFailureResult(t *testing.T) (claimRequest, identity.CommandResult) {
	t.Helper()
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	fields, err := SCIMUserUpdateFields(intent, storageSchema())
	if err != nil {
		t.Fatal(err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: intent.Binding, Operation: scimUserUpdateOperation(intent.Binding.OperationID), Fields: fields})
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	return q, featureOutcome(intent.Binding, q.feature, identity.CommitOutcomeNotCommitted, 0)
}

func TestFeatureFailureJournalWireConservesLegacyAndFiniteCodes(t *testing.T) {
	q, r := featureFailureResult(t)
	legacy, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := encodeJournalResultFailure(q, r, 0, "")
	if err != nil || !bytes.Equal(legacy, zero) {
		t.Fatal("zero code changed legacy journal bytes", err)
	}
	for _, code := range []FeatureFailureCode{FeatureFailureUniqueness, FeatureFailurePrecondition, FeatureFailureConflict} {
		wire, err := encodeJournalResultFailure(q, r, code, "conflict")
		if err != nil {
			t.Fatal(err)
		}
		restored, got, err := decodeJournalResultFailure(q, wire, "conflict")
		if err != nil || got != code || restored.Binding != r.Binding || restored.Outcome != r.Outcome || *restored.Feature != *r.Feature {
			t.Fatal("finite failure did not survive canonical receipt", err)
		}
		if _, err := decodeJournalResult(q, wire); err == nil {
			t.Fatal("legacy-only path silently dropped failure detail")
		}
		old := json.NewDecoder(bytes.NewReader(wire))
		old.DisallowUnknownFields()
		var public identity.CommandResult
		if old.Decode(&public) == nil {
			t.Fatal("old strict public receipt reader did not fail closed")
		}
		for _, bad := range [][]byte{append(bytes.Clone(wire), ' '), bytes.Replace(wire, []byte(`"FeatureFailure":`), []byte(`"featureFailure":`), 1), bytes.Replace(wire, []byte(`"FeatureFailure":1`), []byte(`"FeatureFailure":1,"FeatureFailure":1`), 1)} {
			if bytes.Equal(bad, wire) {
				continue
			}
			if _, _, err := decodeJournalResultFailure(q, bad, "conflict"); err == nil {
				t.Fatal("noncanonical detailed receipt accepted")
			}
		}
		for _, class := range []string{"", "committed", "denied", "dependency-failure"} {
			if _, _, err := decodeJournalResultFailure(q, wire, class); err == nil {
				t.Fatal("finite code escaped conflict terminal class", class)
			}
		}
	}
	for _, code := range []FeatureFailureCode{4, 255} {
		if _, err := encodeJournalResultFailure(q, r, code, "conflict"); err == nil {
			t.Fatal("unknown finite code accepted")
		}
	}
	explicitZero := append(bytes.Clone(legacy[:len(legacy)-1]), []byte(`,"FeatureFailure":0}`)...)
	if _, _, err := decodeJournalResultFailure(q, explicitZero, "conflict"); err == nil {
		t.Fatal("explicit zero changed canonical legacy encoding")
	}
	for _, change := range []func(*identity.CommandResult){
		func(r *identity.CommandResult) {
			r.Outcome = identity.CommitOutcomeCommitted
			r.AuditEventID = "audit"
			r.Feature.BeforeVersion = 7
			r.Feature.AfterVersion = 8
		},
		func(r *identity.CommandResult) { r.Outcome = identity.CommitOutcomeUnknown },
		func(r *identity.CommandResult) { r.Outcome = identity.CommitOutcomeInProgress },
		func(r *identity.CommandResult) { r.Binding.ActorKind = authorization.SubjectUser },
		func(r *identity.CommandResult) { r.Feature.Operation.SchemaID = "foreign" },
	} {
		candidate := r
		feature := *r.Feature
		candidate.Feature = &feature
		change(&candidate)
		if _, err := encodeJournalResultFailure(q, candidate, FeatureFailureUniqueness, "conflict"); err == nil {
			t.Fatal("failure code attached to wrong outcome/owner/schema")
		}
	}
	typed := TypedFeatureFailureError{Code: FeatureFailureUniqueness}
	var conflict identity.ConflictError
	if !errors.As(typed, &conflict) {
		t.Fatal("typed failure broke legacy Conflict compatibility")
	}
}

func featureFailureWork(t *testing.T) (Work, *scimUpdatePlanParticipant, identity.Command) {
	return featureFailureOperationWork(t, scimUserUpdateOperation("identity.scim.user-patch"))
}

func featureFailureOperationWork(t *testing.T, operation identity.FeatureOperation) (Work, *scimUpdatePlanParticipant, identity.Command) {
	t.Helper()
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	fields, err := SCIMUserUpdateFields(intent, storageSchema())
	if err != nil {
		t.Fatal(err)
	}
	intent.Binding.OperationID = operation.OperationID
	intent.Binding.SchemaID = operation.SchemaID
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: intent.Binding, Operation: operation, Fields: fields})
	_, plan := scimUpdatePlanExample()
	plan.Feature.Operation = operation
	p := &scimUpdatePlanParticipant{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}}
	registry, err := NewContributorRegistry([]Contributor{p})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry}
	frozen := &admittedKernelPlan{registry: registry.state, binding: intent.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{1}}
	reservation := &reservationState{coordinator: c, plan: frozen, journal: journalReservation{generation: 3}}
	w := Work{state: &workState{ctx: context.Background(), cancel: func() {}, binding: intent.Binding, generation: 3, registry: registry.state, feature: plan.Feature, subjectType: "scim_user", lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: p, featureApplying: true, featureApplyCommand: &command, execution: &domainExecution{coordinator: c, reservation: reservation}}}
	return w, p, command
}

func TestFeatureFailureDenialPreservesEveryClosedSCIMOperation(t *testing.T) {
	for _, id := range []string{"identity.scim.user-create", "identity.scim.user-replace", "identity.scim.user-patch", "identity.scim.user-delete"} {
		t.Run(id, func(t *testing.T) {
			operation := identity.FeatureOperation{Owner: "scim", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			if id == "identity.scim.user-patch" {
				operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
			}
			w, p, command := featureFailureOperationWork(t, operation)
			err := w.DenyFeature(context.Background(), p, command, FeatureFailureUniqueness)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || w.state.featureFailure != FeatureFailureUniqueness {
				t.Fatal("closed original SCIM operation lost uniqueness denial", err)
			}
			q, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			result := featureOutcome(w.state.binding, &operation, identity.CommitOutcomeNotCommitted, 0)
			wire, err := encodeJournalResultFailure(q, result, FeatureFailureUniqueness, "conflict")
			if err != nil {
				t.Fatal("closed operation could not retain terminal denial", err)
			}
			restored, code, err := decodeJournalResultFailure(q, wire, "conflict")
			if err != nil || code != FeatureFailureUniqueness || restored.Binding != result.Binding || restored.Feature.Operation != operation {
				t.Fatal("closed operation changed retained failure or scope", err)
			}
		})
	}
}

func TestFeatureFailureDenialRequiresOriginalInvocationAndOnlyRefinesConflict(t *testing.T) {
	for _, mode := range []string{"original", "existing-conflict", "foreign", "reconstructed", "tenant-command", "operation-command", "owner", "returned", "closed", "admission", "subject", "actor", "schema", "generation", "nil-context", "cancelled", "unavailable", "forbidden", "invalid-code"} {
		t.Run(mode, func(t *testing.T) {
			w, p, command := featureFailureWork(t)
			ctx := context.Background()
			owner := FeatureExecutionContributor(p)
			code := FeatureFailurePrecondition
			switch mode {
			case "existing-conflict":
				w.state.failed = identity.ConflictError{}
			case "foreign":
				owner = &scimUpdatePlanParticipant{}
			case "reconstructed":
				spec, _ := command.Feature()
				command, _ = identity.NewFeatureCommand(spec)
			case "tenant-command", "operation-command":
				spec, _ := command.Feature()
				if mode == "tenant-command" {
					spec.Binding.TenantID = "foreign-tenant"
				} else {
					spec.Operation.OperationID = "identity.scim.user-delete"
					spec.Operation.SchemaID = "identity.scim.user-delete.native-v1"
					spec.Operation.VersionPolicy = identity.FeatureVersionSequential
					spec.Binding.OperationID = spec.Operation.OperationID
					spec.Binding.SchemaID = spec.Operation.SchemaID
				}
				command = featureCodecCommand(t, spec)
				w.state.featureApplyCommand = &command
			case "owner":
				copy := *w.state.feature
				copy.Operation.Owner = "foreign"
				w.state.feature = &copy
			case "returned":
				w.state.featureInvocation = nil
			case "closed":
				w.state.closed = true
			case "admission":
				w.state.featureApplying = false
			case "subject":
				w.state.subjectType = "user"
			case "actor":
				w.state.binding.ActorKind = authorization.SubjectUser
			case "schema":
				copy := *w.state.feature
				copy.Operation.SchemaVersion++
				w.state.feature = &copy
			case "generation":
				w.state.generation++
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unavailable":
				w.state.failed = identity.UnavailableError{}
			case "forbidden":
				w.state.failed = identity.ForbiddenError{}
			case "invalid-code":
				code = 255
			}
			err := w.DenyFeature(ctx, owner, command, code)
			if mode == "original" || mode == "existing-conflict" {
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || w.state.featureFailure != FeatureFailurePrecondition {
					t.Fatal("exact denial/refinement lost finite custody", err)
				}
			} else if err == nil || w.state.featureFailure != 0 {
				t.Fatal("invalid invocation minted failure detail", err)
			}
		})
	}
	if err := (Work{}).DenyFeature(context.Background(), nil, identity.Command{}, FeatureFailureUniqueness); err == nil {
		t.Fatal("zero Work minted failure")
	}
}

func FuzzFeatureFailureJournalResult(f *testing.F) {
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	op := scimUserUpdateOperation(intent.Binding.OperationID)
	q := claimRequest{safeFields: commandSafeFields(intent.Binding, &op), feature: &op}
	result := featureOutcome(intent.Binding, &op, identity.CommitOutcomeNotCommitted, 0)
	for _, code := range []FeatureFailureCode{0, FeatureFailureUniqueness, FeatureFailurePrecondition, FeatureFailureConflict} {
		wire, err := encodeJournalResultFailure(q, result, code, "conflict")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		r, code, err := decodeJournalResultFailure(q, wire, "conflict")
		if err != nil {
			return
		}
		canonical, err := encodeJournalResultFailure(q, r, code, "conflict")
		if err != nil || !bytes.Equal(canonical, wire) {
			t.Fatal("noncanonical finite receipt accepted")
		}
	})
}
