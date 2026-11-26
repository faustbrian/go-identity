package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type scimBulkUnavailableTestOwner struct {
	*scimBulkUserFailureParticipant
	start func(context.Context, Work, identity.Command) error
}

func (p *scimBulkUnavailableTestOwner) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, p.start(ctx, w, command)
}

func (*scimBulkUnavailableTestOwner) RecordSCIMBulkChildUnavailable(context.Context, Work) error {
	return nil
}

func scimBulkUnavailableWork(t *testing.T, operation identity.FeatureOperation) (Work, *scimBulkUnavailableTestOwner, identity.Command) {
	t.Helper()
	c, w, participant := scimBulkUserFailureFixture(t, operation)
	owner := &scimBulkUnavailableTestOwner{scimBulkUserFailureParticipant: participant}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	c.registry, w.state.registry = registry, registry.state
	plan := w.state.execution.reservation.plan
	plan.binding.PolicyID, plan.binding.PolicyVersion = "scope-policy", 1
	plan.fingerprint = [32]byte{1}
	w.state.binding, w.state.generation = plan.binding, 3
	w.state.execution.reservation.journal.generation = 3
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: plan.binding, Operation: operation})
	owner.start = func(ctx context.Context, w Work, command identity.Command) error {
		return w.MarkSCIMBulkChildStarted(ctx, owner, command)
	}
	return w, owner, command
}

func TestSCIMBulkUnavailablePlan(t *testing.T) {
	for _, operation := range []identity.FeatureOperation{
		scimUserCreationOperation(),
		groupFailureOperation("identity.scim.group-create"),
		groupFailureOperation("identity.scim.group-replace"),
		groupFailureOperation("identity.scim.group-patch"),
		groupFailureOperation("identity.scim.group-delete"),
	} {
		t.Run(operation.OperationID, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				change func(*admittedKernelPlan)
			}{
				{name: "original"},
				{name: "ordinary_audit", change: func(p *admittedKernelPlan) { p.audits[0].EventType = operation.OperationID }},
				{name: "unprotected_audit", change: func(p *admittedKernelPlan) { p.audits[0].RetentionClass = "ordinary" }},
				{name: "wrong_owner", change: func(p *admittedKernelPlan) { p.feature.Operation.Owner = "other" }},
				{name: "wrong_contributor", change: func(p *admittedKernelPlan) { p.feature.Contributor.ContractID = "other" }},
				{name: "wrong_binding_operation", change: func(p *admittedKernelPlan) { p.binding.OperationID = "identity.scim.other" }},
				{name: "wrong_binding_schema", change: func(p *admittedKernelPlan) { p.binding.SchemaID = "other.native-v1" }},
				{name: "wrong_binding_version", change: func(p *admittedKernelPlan) { p.binding.SchemaVersion++ }},
				{name: "missing_record", change: func(p *admittedKernelPlan) { p.binding.RecordID = "" }},
				{name: "wrong_subject", change: func(p *admittedKernelPlan) { p.subjectType = "other" }},
				{name: "invalid_parent", change: func(p *admittedKernelPlan) { p.binding.CorrelationID = "not-a-command" }},
				{name: "same_command_parent", change: func(p *admittedKernelPlan) { p.binding.CorrelationID = string(p.binding.CommandID) }},
				{name: "human_actor", change: func(p *admittedKernelPlan) { p.binding.ActorKind = authorization.SubjectUser }},
				{name: "denial_only", change: func(p *admittedKernelPlan) { p.scimBulkDenial, p.lifecycle = FeatureFailureSCIMBulkDependency, nil }},
				{name: "no_lifecycle", change: func(p *admittedKernelPlan) { p.lifecycle = nil }},
				{name: "no_feature", change: func(p *admittedKernelPlan) { p.feature = nil }},
			} {
				t.Run(test.name, func(t *testing.T) {
					w, _, _ := scimBulkUnavailableWork(t, operation)
					plan := w.state.execution.reservation.plan
					if test.change != nil {
						test.change(plan)
					}
					if got, want := scimBulkUnavailablePlan(plan), test.name == "original"; got != want {
						t.Fatalf("unavailable child eligibility = %v, want %v", got, want)
					}
				})
			}
		})
	}
	if scimBulkUnavailablePlan(nil) {
		t.Fatal("missing plan acquired unavailable-child settlement authority")
	}
}

func TestMarkSCIMBulkChildStarted(t *testing.T) {
	for _, mode := range []string{"original", "original_group", "no_invocation", "cross_invocation", "closed", "admission_only", "reconstructed_command", "component", "repeat"} {
		t.Run(mode, func(t *testing.T) {
			operation := scimUserCreationOperation()
			if mode == "original_group" {
				operation = groupFailureOperation("identity.scim.group-create")
			}
			w, owner, command := scimBulkUnavailableWork(t, operation)
			owner.start = func(ctx context.Context, w Work, command identity.Command) error {
				participant := owner
				switch mode {
				case "no_invocation":
					w.state.featureInvocation = nil
				case "cross_invocation":
					participant = &scimBulkUnavailableTestOwner{scimBulkUserFailureParticipant: owner.scimBulkUserFailureParticipant}
				case "closed":
					w.state.closed = true
				case "admission_only":
					w.state.featureApplying = false
				case "reconstructed_command":
					spec, _ := command.Feature()
					command = featureCodecCommand(t, spec)
				case "component":
					w.state.execution.component = true
				case "repeat":
					if err := w.MarkSCIMBulkChildStarted(ctx, owner, command); err != nil {
						t.Fatal("original start failed", err)
					}
				}
				return w.MarkSCIMBulkChildStarted(ctx, participant, command)
			}
			_, err := invokeFeature(owner, t.Context(), w, command)
			wantSuccess := mode == "original" || mode == "original_group"
			wantStarted := wantSuccess || mode == "repeat"
			if w.state.scimBulkChildStarted != wantStarted || (err == nil) != wantSuccess {
				t.Fatalf("start marker = %v, error = %v; expected started = %v and success = %v", w.state.scimBulkChildStarted, err, wantStarted, wantSuccess)
			}
			if w.state.featureInvocation != nil || w.state.featureApplying || w.state.featureApplyCommand != nil {
				t.Fatal("returned invocation retained Apply custody")
			}
		})
	}
	w, owner, command := scimBulkUnavailableWork(t, scimUserCreationOperation())
	owner.start = func(context.Context, Work, identity.Command) error { return nil }
	if _, err := invokeFeature(owner, t.Context(), w, command); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkSCIMBulkChildStarted(t.Context(), owner, command); err == nil || w.state.scimBulkChildStarted {
		t.Fatal("returned invocation acquired start custody")
	}
}
