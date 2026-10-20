package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type oauthHandoffProbe struct{ outputPreparationParticipant }

func (*oauthHandoffProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
}
func (*oauthHandoffProbe) OAuthContinuationHandoff(identity.Command) (identity.CommandID, bool, error) {
	return "", false, nil
}
func (*oauthHandoffProbe) AdvanceOAuthContinuation(context.Context, Work, identity.Command, identity.CommandID) error {
	return nil
}
func (*oauthHandoffProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return OAuthReauthenticationRequiredError{}
}

func TestOAuthReauthenticationFinalCheckPreservesTypedTerminalFailure(t *testing.T) {
	spec := featureCodecSpec()
	spec.Operation = oauthContinuationOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	command := featureCodecCommand(t, spec)
	owner := &oauthHandoffProbe{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry}
	w := Work{state: &workState{ctx: t.Context(), registry: registry.state, binding: spec.Binding,
		feature:          &FeatureRegistration{Contributor: owner.Descriptor(), Operation: spec.Operation},
		featureAttempted: true, featureReceipt: &identity.FeatureReceipt{Operation: spec.Operation}, featureCommitCommand: &command,
		execution: &domainExecution{coordinator: c, reservation: &reservationState{}},
	}}
	err = c.checkFeatureCommit(w)
	var reauthenticate OAuthReauthenticationRequiredError
	if !errors.As(err, &reauthenticate) || !errors.As(w.usable(), &reauthenticate) || w.state.featureInvocation != nil {
		t.Fatal("final native expiry lost terminal class or retained callback permission", err)
	}
}

func TestOAuthReauthenticationFailurePoisonsWorkWithoutLosingClassification(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(fmt.Sprint(selected), func(t *testing.T) {
			feature := &FeatureRegistration{Contributor: (&oauthHandoffProbe{}).Descriptor(), Operation: oauthContinuationOperation()}
			if !selected {
				feature.Operation = featureCodecSpec().Operation
			}
			w := Work{state: &workState{ctx: t.Context(), feature: feature}}
			err := w.fail(t.Context(), OAuthReauthenticationRequiredError{})
			var reauthenticate OAuthReauthenticationRequiredError
			if errors.As(err, &reauthenticate) != selected || w.state.failed == nil || w.usable() != err {
				t.Fatal("work lost the selected terminal denial or admitted foreign retry semantics", err)
			}
			if selected {
				class, _, _, _ := abortClassification(err)
				if class != "reauthentication-required" {
					t.Fatal("poisoned Work cannot produce its original terminal class")
				}
			}
		})
	}
}

func TestOAuthContinuationHandoffGuardRejectsOtherInvocationsAndAllAliases(t *testing.T) {
	_, command, _ := featurePlanFixture(t)
	owner := &oauthHandoffProbe{}
	previous := identity.CommandID("AgICAgICAgICAgICAgICAg")
	newWork := func() Work {
		return Work{state: &workState{ctx: t.Context(), featureInvocation: owner, oauthHandoff: &oauthContinuationHandoff{owner: owner, command: command, previous: previous}}}
	}
	if err := newWork().RequireOAuthContinuationHandoff(t.Context(), owner, command, previous); err != nil {
		t.Fatal("exact live callback denied", err)
	}
	for name, mutate := range map[string]func(*workState){
		"admission-only": func(s *workState) { s.oauthHandoff = nil },
		"returned":       func(s *workState) { s.featureInvocation = nil },
		"foreign-owner":  func(s *workState) { s.featureInvocation = &oauthHandoffProbe{} },
		"other-command":  func(s *workState) { s.oauthHandoff.command = identity.Command{} },
		"other-attempt":  func(s *workState) { s.oauthHandoff.previous = "AwMDAwMDAwMDAwMDAwMDAw" },
		"apply":          func(s *workState) { s.featureApplying = true },
		"execution":      func(s *workState) { s.execution = &domainExecution{} },
		"closed":         func(s *workState) { s.closed = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWork()
			alias := w
			mutate(w.state)
			if err := alias.RequireOAuthContinuationHandoff(t.Context(), owner, command, previous); err == nil || w.usable() == nil {
				t.Fatal("non-owning handoff acquired permission or retained usable alias")
			}
		})
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(t.Context()); cancel(); return ctx }()} {
		if err := newWork().RequireOAuthContinuationHandoff(ctx, owner, command, previous); err == nil {
			t.Fatal("missing/cancelled callback context admitted")
		}
	}
	if err := (Work{}).RequireOAuthContinuationHandoff(t.Context(), owner, command, previous); err == nil {
		t.Fatal("zero Work admitted")
	}
}

func TestOAuthReauthenticationReceiptPreservesOriginalNotCommittedAndScope(t *testing.T) {
	_, _, plan := featurePlanFixture(t)
	spec := featureCodecSpec()
	spec.Operation = oauthContinuationOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	descriptor := (&oauthHandoffProbe{}).Descriptor()
	plan.Feature = &FeatureRegistration{Operation: spec.Operation, Contributor: descriptor}
	plan.Contributors[len(plan.Contributors)-1] = descriptor
	q, err := prepareClaim(featureCodecCommand(t, spec), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte(queryFingerprint()), plan)
	if err != nil {
		t.Fatal("original feature history", err)
	}
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: spec.Operation}}
	body, err := encodeJournalResult(q, result)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, class, version := "aborted", "reauthentication-required", int32(1)
	observed := commandObservation{tenant: string(spec.Binding.TenantID), purpose: spec.Binding.OperationID, scope: q.safeFields, fingerprint: queryFingerprint(), plan: wire, state: &state, until: &now, now: now, resultVersion: &version, class: &class, result: body}
	query, _ := queryInputs(spec.Binding)
	got, err := commandReceipt(query, observed, nil)
	var reauthenticate OAuthReauthenticationRequiredError
	if !errors.As(err, &reauthenticate) || !reflect.DeepEqual(got, result) {
		t.Fatal("original failed attempt cannot be recovered with its exact class", err)
	}
	query.UserID = "foreign"
	got, err = commandReceipt(query, observed, nil)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || !reflect.DeepEqual(got, identity.CommandResult{}) {
		t.Fatal("foreign caller learned historical attempt")
	}
	query, _ = queryInputs(spec.Binding)
	observed.plan = []byte{1}
	got, err = commandReceipt(query, observed, nil)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, identity.CommandResult{}) {
		t.Fatal("corrupt history became permission to retry")
	}
}

func TestOAuthReauthenticationRemainsDistinctTerminalDenial(t *testing.T) {
	class, reason, outcome, safe := abortClassification(fmt.Errorf("synthetic wrapping: %w", OAuthReauthenticationRequiredError{}))
	var expected OAuthReauthenticationRequiredError
	if class != "reauthentication-required" || reason != "not_authorized" || outcome != audit.OutcomeDenied || !errors.As(safe, &expected) {
		t.Fatal("actual OAuth age expiry became dependency failure")
	}
}

func TestOAuthReauthenticationClassificationCannotEscapeItsFeatureOwner(t *testing.T) {
	canonical := &FeatureRegistration{Contributor: (&oauthHandoffProbe{}).Descriptor(), Operation: oauthContinuationOperation()}
	for _, registered := range []*FeatureRegistration{nil, canonical, {Contributor: (&scopeFeatureParticipant{}).Descriptor(), Operation: canonical.Operation}, {Contributor: canonical.Contributor, Operation: featureCodecSpec().Operation}} {
		class, _, _, safe := abortFeatureClassification(OAuthReauthenticationRequiredError{}, registered)
		var reauthenticate OAuthReauthenticationRequiredError
		selected := registered == canonical
		if (class == "reauthentication-required") != selected || errors.As(safe, &reauthenticate) != selected {
			t.Fatal("foreign command acquired an unrecoverable OAuth-only terminal class")
		}
	}
}

func TestOAuthContinuationHandoffRetainsExactHumanAndOriginalFlowScope(t *testing.T) {
	op := oauthContinuationOperation()
	current := codecBinding()
	current.OperationID, current.SchemaID, current.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	current.ActorKind, current.ActorID = authorization.SubjectUser, identity.ActorID(current.UserID)
	current.RecordID = "original-grant"
	current.CorrelationID = string(current.CommandID)
	previous := current
	previous.CommandID = "AgICAgICAgICAgICAgICAg"
	previous.CorrelationID = string(previous.CommandID)
	if !oauthContinuationHandoffScope(current, previous) {
		t.Fatal("same original human continuation cannot hand off a failed attempt")
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CommandID = current.CommandID },
		func(b *identity.CommandBinding) { b.CommandID = "invalid" },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID, b.ActorID = "other", "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		func(b *identity.CommandBinding) { b.RecordID = "other-grant" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.oauth-server.authorize" },
		func(b *identity.CommandBinding) { b.SchemaID = "other" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.PolicyID = "other" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other" },
		func(b *identity.CommandBinding) { b.CorrelationID = "other" },
	} {
		changed := previous
		mutate(&changed)
		if oauthContinuationHandoffScope(current, changed) {
			t.Fatal("handoff widened immutable predecessor scope")
		}
	}
}
