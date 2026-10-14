package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func anonymousFeatureCodecSpec() identity.FeatureCommandSpec {
	s := featureCodecSpec()
	s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	s.Binding.UserID, s.Binding.AnonymousFlowID = "", "anonymous-flow"
	return s
}

func TestAnonymousFeatureRecordFreeAuditTargetsFlowNotUser(t *testing.T) {
	s := anonymousFeatureCodecSpec()
	s.Operation.RecordRequirement, s.Binding.RecordID = identity.FeatureRecordOmitted, ""
	b := s.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "anonymous.checked", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous_flow", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous_flow", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FeatureAuditBindingDigest(b, s.Operation, "anonymous_flow", r); err != nil {
		t.Fatal("anonymous audit target was replaced with empty user", err)
	}
}

func TestAnonymousFeatureRecordFreeLifecycleAndMutationAuditConserveFlow(t *testing.T) {
	w, original, ap := auditFixture(t)
	s := anonymousFeatureCodecSpec()
	s.Operation.RecordRequirement, s.Binding.RecordID = identity.FeatureRecordOmitted, ""
	w.state.binding = s.Binding
	w.state.subjectType = "anonymous_flow"
	w.state.feature = &FeatureRegistration{Operation: s.Operation}
	r := changedAudit(t, original, func(in *audit.RecordInput) {
		in.Action, in.Subject.Type, in.Subject.ID = "anonymous.checked", "anonymous_flow", s.Binding.AnonymousFlowID
		in.Actor.ID = string(s.Binding.ActorID)
		in.Attributes["command.id"] = string(s.Binding.CommandID)
		in.Attributes["aggregate.type"], in.Attributes["aggregate.id"] = "anonymous_flow", s.Binding.AnonymousFlowID
		in.Attributes["aggregate.after_version"] = "0"
	}, "", true)
	ap.EventType = r.Action()
	ap.RetentionClass = "standard"
	var err error
	ap.BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "anonymous_flow", r)
	if err != nil {
		t.Fatal(err)
	}
	if err = bindAuditPlans(w, []AuditPlan{ap}); err != nil {
		t.Fatal(err)
	}
	if err = w.StageAudit(ap.EventIndex, r); err != nil {
		t.Fatal(err)
	}
	l := LifecyclePlan{EventType: "anonymous.checked.v1"}
	if err = bindLifecyclePlan(w, &l); err != nil {
		t.Fatal(err)
	}
	if err = w.StageLifecycle(0, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	records, err := w.StagedLifecycle()
	if err != nil || len(records) != 1 || records[0].UserID != "" || records[0].SubjectType != "anonymous_flow" || records[0].SubjectID != s.Binding.AnonymousFlowID {
		t.Fatal("anonymous lifecycle lost its namespace", err)
	}
	p := &admittedKernelPlan{binding: s.Binding, subjectType: "anonymous_flow", audits: []AuditPlan{ap}, lifecycle: &l}
	mutations, err := featureMutationAudits(context.Background(), p, time.Now().UTC().Truncate(time.Microsecond), "committed")
	if err != nil || len(mutations) != 1 || mutations[0].Subject().ID() != s.Binding.AnonymousFlowID || mutations[0].Actor().ID() != string(s.Binding.ActorID) {
		t.Fatal("mutation audit substituted flow or actor", err)
	}
}

func TestAnonymousFeatureScopeAndPlanConserveDistinctNamespace(t *testing.T) {
	s := anonymousFeatureCodecSpec()
	claim, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	b, f, err := decodeObservedScope(claim.safeFields)
	if err != nil || b != s.Binding || f == nil || *f != s.Operation {
		t.Fatal("anonymous scope was dropped or confused with user", err)
	}
	s.Binding.AnonymousFlowID = "another-flow"
	other, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil || bytes.Equal(claim.canonical, other.canonical) || bytes.Equal(claim.safeFields, other.safeFields) {
		t.Fatal("different anonymous flows share command identity", err)
	}
	_, command, p := featurePlanFixture(t)
	spec, _ := command.Feature()
	spec.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	spec.Binding.UserID, spec.Binding.AnonymousFlowID = "", "anonymous-flow"
	p.Feature.Operation = spec.Operation
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || plan.Feature == nil || plan.Feature.Operation != spec.Operation {
		t.Fatal("historical plan lost subject namespace", err)
	}
}

func TestAnonymousFeatureAdmissionUsesExactSeparateResource(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	s := anonymousFeatureCodecSpec()
	q := identity.RecoveryQuery{CommandID: s.Binding.CommandID, TenantID: s.Binding.TenantID, AnonymousFlowID: s.Binding.AnonymousFlowID, ActorID: s.Binding.ActorID, ActorKind: s.Binding.ActorKind, OperationID: s.Binding.OperationID, RecordID: s.Binding.RecordID}
	_, caller := queryInputs(s.Binding)
	caller.Request.Resource.Type, caller.Request.Resource.ID = "identity.anonymous-flow", authorization.ResourceID(q.AnonymousFlowID)
	c.admissionPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		return commandObservation{}, pgx.ErrNoRows
	}
	got, err := c.ObserveCommandAdmission(context.Background(), q, caller)
	if err != nil || !got.Absent {
		t.Fatal("explicit anonymous admission rejected", err)
	}
	for _, mutate := range []func(*authorization.DecisionContext){
		func(d *authorization.DecisionContext) { d.Request.Resource.Type = "identity.user" },
		func(d *authorization.DecisionContext) { d.Request.Resource.ID = "another-flow" },
		func(d *authorization.DecisionContext) { d.Request.Subject.ID = "other-actor" },
		func(d *authorization.DecisionContext) { d.Request.Tenant = "other-tenant" },
	} {
		wrong := caller.Clone()
		mutate(&wrong)
		denied, err := c.ObserveCommandAdmission(context.Background(), q, wrong)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || denied != (CommandAdmission{}) {
			t.Fatal("foreign namespace or scope admitted", err)
		}
	}
	q.UserID = "mixed-user"
	if got, err := c.ObserveCommandAdmission(context.Background(), q, caller); err == nil || got != (CommandAdmission{}) {
		t.Fatal("mixed user and anonymous namespace admitted")
	}
}
