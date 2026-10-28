package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This participant proves the coordinator's native invocation boundary, not
// an API-key digest comparison or current owner/policy authority.
type apiKeyVerificationTestParticipant struct {
	outcome           APIKeyVerificationOutcome
	verificationCalls int
	genericCalls      int
}

func (*apiKeyVerificationTestParticipant) Descriptor() ContributorDescriptor {
	return apiKeyVerificationDescriptor()
}

func (*apiKeyVerificationTestParticipant) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{apiKeyVerificationOperation(false), apiKeyVerificationOperation(true)}
}

func (*apiKeyVerificationTestParticipant) ValidateFeatureCommand(_ identity.Command, p CommandPlan) error {
	if p.APIKeyVerification == nil {
		return invalidPlan()
	}
	return nil
}

func (p *apiKeyVerificationTestParticipant) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	p.genericCalls++
	return identity.FeatureReceipt{}, nil
}

func (p *apiKeyVerificationTestParticipant) ApplyAPIKeyVerification(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, APIKeyVerificationOutcome, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, APIKeyVerificationOutcome{}, err
	}
	p.verificationCalls++
	spec, _ := command.Feature()
	return identity.FeatureReceipt{Operation: spec.Operation}, p.outcome, nil
}

func (*apiKeyVerificationTestParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return nil
}

func (*apiKeyVerificationTestParticipant) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func apiKeyVerificationRuntimeFixture(t *testing.T, anonymous bool) (*Coordinator, identity.Command, CommandPlan, *apiKeyVerificationTestParticipant) {
	t.Helper()
	c, _, _ := coordinatorFixture(t)
	b, p := apiKeyVerificationPlanFixture(t, anonymous)
	native := &apiKeyVerificationTestParticipant{}
	entries := []Contributor{
		finalTestDomain{c.registry.state.entries[0].contributor},
		finalTestAudit{c.registry.state.entries[1].contributor.(*planAuditContributor)},
		finalTestLifecycle{c.registry.state.entries[2].contributor.(*planLifecycleContributor)},
		native,
	}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	p.Contributors = registry.Descriptors()
	p.Feature.Contributor = native.Descriptor()
	if anonymous {
		p.SubjectType = "authentication_attempt"
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := range p.Audits {
		probe, err := securityMutationAudit(t.Context(), b, 0, 0, now, "denied", p.Audits[i].EventType, p.SubjectType, featureAuditTargetID(b, p.Feature.Operation), "protected", true)
		if err != nil {
			t.Fatal(err)
		}
		p.Audits[i].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, probe)
		if err != nil {
			t.Fatal(err)
		}
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	if err != nil {
		t.Fatal(err)
	}
	return c, command, p, native
}

func TestAPIKeyVerificationPreparationRetainsNativeDeclaration(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		name := "known-key"
		if anonymous {
			name = "unknown-key"
		}
		t.Run(name, func(t *testing.T) {
			c, command, declaration, _ := apiKeyVerificationRuntimeFixture(t, anonymous)
			spec, _ := command.Feature()
			prepared, err := c.PrepareCommandPlan(spec.Binding, command, declaration)
			if err != nil {
				t.Fatal("native verification declaration was lost or rejected before reservation", err)
			}
			q, err := prepareClaim(command, c.keys.retained[c.keys.current])
			if err != nil {
				t.Fatal(err)
			}
			admitted, err := c.registry.admitFeaturePlan(spec.Binding, claimFingerprint(c.keys.retained[c.keys.current], q.canonical), prepared)
			if err != nil || admitted.apiKeyVerification == nil || *admitted.apiKeyVerification != *declaration.APIKeyVerification {
				t.Fatal("admitted plan omitted verification ownership", err)
			}
			declaration.APIKeyVerification.KeyVersion++
			if admitted.snapshot().APIKeyVerification.KeyVersion != prepared.APIKeyVerification.KeyVersion {
				t.Fatal("caller changed retained verification declaration")
			}
		})
	}
}

func apiKeyVerificationInvocationFixture(t *testing.T, anonymous bool) (*Coordinator, Work, identity.Command, *apiKeyVerificationTestParticipant) {
	t.Helper()
	c, command, p, native := apiKeyVerificationRuntimeFixture(t, anonymous)
	spec, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := c.registry.admitFeaturePlan(spec.Binding, claimFingerprint(c.keys.retained[c.keys.current], q.canonical), prepared)
	if err != nil {
		t.Fatal(err)
	}
	r := &reservationState{plan: admitted, request: q, journal: journalReservation{generation: 1}}
	w := Work{state: &workState{ctx: t.Context(), binding: spec.Binding, generation: 1, registry: c.registry.state}}
	if err := admitted.bindWork(w); err != nil {
		t.Fatal(err)
	}
	w.state.execution = &domainExecution{coordinator: c, reservation: r}
	return c, w, command, native
}

func TestAPIKeyVerificationInvocationUsesTypedNativeComparison(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		outcome   APIKeyVerificationOutcome
	}{
		{"allowed", false, APIKeyVerificationOutcome{Authenticated: true}},
		{"denied", false, APIKeyVerificationOutcome{}},
		{"narrow-allowed", false, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: true}},
		{"narrow-denied", false, APIKeyVerificationOutcome{PermissionsChanged: true}},
		{"unknown-denied", true, APIKeyVerificationOutcome{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w, command, native := apiKeyVerificationInvocationFixture(t, tc.anonymous)
			native.outcome = tc.outcome
			receipt, err := invokeFeature(native, t.Context(), w, command)
			spec, _ := command.Feature()
			if err != nil || receipt != (identity.FeatureReceipt{Operation: spec.Operation}) || native.verificationCalls != 1 || native.genericCalls != 0 {
				t.Fatal("verification escaped its typed native comparison", err)
			}
			if _, _, _, err := w.FeatureCommandIdentity(native); err == nil {
				t.Fatal("verification retained invocation authority after return")
			}
		})
	}
}

func TestAPIKeyVerificationAdmissionRequiresTypedComparisonAndFinalFence(t *testing.T) {
	c, command, p, native := apiKeyVerificationRuntimeFixture(t, false)
	// Hide the additional native phases while preserving the exact descriptor
	// and generic feature API. Registration alone cannot confer those phases.
	generic := struct{ FeatureExecutionContributor }{native}
	entries := []Contributor{
		c.registry.state.entries[0].contributor,
		c.registry.state.entries[1].contributor,
		c.registry.state.entries[2].contributor,
		generic,
	}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	spec, _ := command.Feature()
	if _, err := c.PrepareCommandPlan(spec.Binding, command, p); err == nil {
		t.Fatal("generic mutation adapter admitted as credential comparison/final authority")
	}
}
