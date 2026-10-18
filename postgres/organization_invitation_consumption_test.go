package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Pure invocation fixture, not proof of SQL consumption or actual membership.
// The real adapter consumer must separately demonstrate atomic durable effects.
func invitationInvocationFixture(t *testing.T, before uint64) (Work, *invitationConsumptionProbe) {
	t.Helper()
	b, p := organizationInvitationPlanFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{
		{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "org-a"}},
		{Name: "organization.member-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: before}},
	}})
	owner := &invitationConsumptionProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}, expected: command, proof: *p.Capability}
	plan := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, capability: p.Capability}
	r := &reservationState{plan: plan, journal: journalReservation{generation: 1}}
	w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, subjectType: "invitation", lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, invitationConsumed: true, execution: &domainExecution{reservation: r}}}
	return w, owner
}

func TestOrganizationInvitationConsumptionRequiresExactProtectedInvocation(t *testing.T) {
	for _, mode := range []string{"current", "not consumed", "finalized", "returned", "commit", "foreign", "closed", "wrong operation", "missing proof"} {
		t.Run(mode, func(t *testing.T) {
			w, owner := invitationInvocationFixture(t, 2)
			candidate := owner
			switch mode {
			case "not consumed":
				w.state.invitationConsumed = false
			case "finalized":
				w.state.invitationFinalized = true
			case "returned":
				w.state.featureInvocation = nil
			case "commit":
				w.state.featureApplying = false
			case "foreign":
				candidate = &invitationConsumptionProbe{}
			case "closed":
				w.state.closed = true
			case "wrong operation":
				w.state.feature.Operation = magicLinkConsumeOperation()
			case "missing proof":
				w.state.execution.reservation.plan.capability = nil
			}
			got, err := w.OrganizationInvitationConsumption(candidate)
			if mode != "current" {
				if err == nil || got != (CapabilityReservationBinding{}) {
					t.Fatal("foreign phase acquired original proof")
				}
				return
			}
			if err != nil || got.Command != w.state.binding || got.Generation != 1 || got.Plan != owner.proof {
				t.Fatal("original custody lost", err)
			}
			got.Plan.ProofFingerprint[0]++
			if w.state.execution.reservation.plan.capability.ProofFingerprint != owner.proof.ProofFingerprint {
				t.Fatal("projection aliases original")
			}
		})
	}
	if got, err := (Work{}).OrganizationInvitationConsumption(&invitationConsumptionProbe{}); err == nil || got != (CapabilityReservationBinding{}) {
		t.Fatal("zero Work exposed original")
	}
}

func TestOrganizationInvitationMemberReceiptPoisonsIgnoredWrongOwner(t *testing.T) {
	w, _ := invitationInvocationFixture(t, 2)
	if err := w.RecordOrganizationInvitationMembership(&invitationConsumptionProbe{}, OrganizationInvitationMembership{OrganizationID: "org-a", UserID: w.state.binding.UserID, BeforeVersion: 2, AfterVersion: 3}); err == nil {
		t.Fatal("foreign receipt admitted")
	}
	if w.usable() == nil {
		t.Fatal("ignored foreign receipt rejection leaves transaction usable")
	}
}

func TestOrganizationInvitationMemberEventUsesActualTombstone(t *testing.T) {
	for _, before := range []uint64{0, 2, 9} {
		t.Run(string(rune('a'+before)), func(t *testing.T) {
			w, owner := invitationInvocationFixture(t, before)
			mutation := OrganizationInvitationMembership{OrganizationID: "org-a", UserID: w.state.binding.UserID, BeforeVersion: before, AfterVersion: before + 1}
			if err := w.RecordOrganizationInvitationMembership(owner, mutation); err != nil {
				t.Fatal("actual mutation receipt rejected", err)
			}
			mutation.AfterVersion++
			if _, err := w.StagedOrganizationInvitationMembership(); err == nil {
				t.Fatal("unstaged primary yielded member event")
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			p := w.state.execution.reservation.plan
			_, declaration := organizationInvitationPlanFixture(t)
			p.audits = declaration.Audits
			record, err := securityMutationAudit(t.Context(), w.state.binding, 1, 2, now, "committed", declaration.Audits[0].EventType, "invitation", w.state.binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			p.audits[0].BindingDigest, err = FeatureAuditBindingDigest(w.state.binding, p.feature.Operation, "invitation", record)
			if err != nil {
				t.Fatal(err)
			}
			if err = bindAuditPlans(w, p.audits); err != nil {
				t.Fatal(err)
			}
			if err = w.StageAudit(0, record); err != nil {
				t.Fatal(err)
			}
			if err = w.StageLifecycle(0, now); err != nil {
				t.Fatal(err)
			}
			w.state.featureReceipt = &identity.FeatureReceipt{Operation: p.feature.Operation, BeforeVersion: 1, AfterVersion: 2}
			got, err := w.StagedOrganizationInvitationMembership()
			if err != nil || got.EventType != "membership.created.v1" || got.SubjectType != "organization" || got.SubjectID != "org-a" || got.UserID != w.state.binding.UserID || got.BeforeVersion != before || got.AfterVersion != before+1 || got.EventIndex != 1 || got.OccurredAt != now {
				t.Fatal("member event substituted invitation version/scope", got, err)
			}
			primary, _ := w.StagedLifecycle()
			if got.ID == primary[0].ID {
				t.Fatal("secondary event collides with primary")
			}
			got.SubjectID = "foreign"
			again, err := w.StagedOrganizationInvitationMembership()
			if err != nil || again.SubjectID != "org-a" {
				t.Fatal("event copy changed staged original", err)
			}
			if err = w.RecordOrganizationInvitationMembership(owner, mutation); err == nil || w.usable() == nil {
				t.Fatal("repeated receipt allowed usable Work")
			}
		})
	}
}
