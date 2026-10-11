package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This participant tests pure native custody dispatch, not factor verification,
// token signing, durable continuation storage or public MFA authentication.
type magicLinkMFAValidationParticipant struct {
	magicLinkPreparationParticipant
	challenge MFAContinuationPlan
}

// Exercise the invocation capability, not PostgreSQL consumption/persistence.
// Those effects require the actual durable consumer journey before adoption.
func TestMagicLinkMFAProjectionRequiresProtectedConsumedInvocation(t *testing.T) {
	b, p := magicLinkMFAPlanFixture(t)
	owner := &magicLinkMFAValidationParticipant{}
	for _, mode := range []string{"current", "before consumption", "finalized", "returned", "commit check", "foreign", "missing scope", "missing child", "session event", "closed"} {
		t.Run(mode, func(t *testing.T) {
			frozen := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: &LifecyclePlan{EventType: "mfa.challenge.created.v1"}, fingerprint: [32]byte{7}, capability: p.Capability, mfaContinuation: cloneMFAContinuationPlan(p.MFAContinuation), issuance: cloneCapabilityIssuancePlan(p.CapabilityIssuance)}
			r := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, lifecycle: &workLifecycle{plan: *frozen.lifecycle}, featureInvocation: owner, featureApplying: true, magicLinkConsumed: true, execution: &domainExecution{reservation: r}}}
			candidate := owner
			switch mode {
			case "before consumption":
				w.state.magicLinkConsumed = false
			case "finalized":
				w.state.magicLinkFinalized = true
			case "returned":
				w.state.featureInvocation = nil
			case "commit check":
				w.state.featureApplying = false
			case "foreign":
				candidate = &magicLinkMFAValidationParticipant{}
			case "missing scope":
				frozen.mfaContinuation = nil
			case "missing child":
				frozen.issuance = nil
			case "session event":
				frozen.lifecycle.EventType = "session.created.v1"
			case "closed":
				w.state.closed = true
			}
			got, err := w.MagicLinkMFAChallenge(candidate)
			if mode != "current" {
				if err == nil || got != (MFAContinuationPlan{}) {
					t.Fatal("unowned phase acquired challenge scope")
				}
				return
			}
			if err != nil || got != *p.MFAContinuation {
				t.Fatal("protected scope lost", err)
			}
			got.ScopeDigest[0]++
			if frozen.mfaContinuation.ScopeDigest != p.MFAContinuation.ScopeDigest {
				t.Fatal("projection mutated original challenge")
			}
		})
	}
}

func TestMagicLinkMFAPreparationRequiresExactOwnerAndOwnsScope(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, final := magicLinkMFAPlanFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: final.Capability.CapabilityID}}}})
	owner := &magicLinkMFAValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{magicLinkConsumeOperation()}}}, expected: command, proof: *final.Capability}, challenge: *final.MFAContinuation}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{final.Contributors[1]}}, &riskPassiveProbe{registryContributor{final.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}, &issuancePlanProbe{}}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	final.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", final.Audits[0].EventType, final.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	final.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, magicLinkConsumeOperation(), final.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	prepared, err := c.PrepareFeaturePreparationPlan(command, original)
	if err != nil || prepared.MFAContinuation == nil || *prepared.MFAContinuation != owner.challenge {
		t.Fatal("exact owner cannot retain original challenge preparation", err)
	}
	_, admitted, _, err := c.prepareFeaturePreparation(command, prepared)
	if err != nil || admitted == nil || admitted.mfaContinuation == nil || *admitted.mfaContinuation != owner.challenge {
		t.Fatal("admission dropped original MFA scope", err)
	}
	prepared.MFAContinuation.ScopeDigest[0]++
	if admitted.mfaContinuation.ScopeDigest != owner.challenge.ScopeDigest {
		t.Fatal("caller changed admitted challenge")
	}
	if _, err := c.PrepareFeaturePreparationPlan(command, prepared); err == nil {
		t.Fatal("original preparation skipped native MFA scope authentication")
	}
	if _, err := c.PrepareCommandPlan(b, command, final); err != nil {
		t.Fatal("generated issuer confused with original consuming participant", err)
	}
	entries[3] = &owner.magicLinkPreparationParticipant
	withoutMFA, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = withoutMFA
	if _, err := c.PrepareFeaturePreparationPlan(command, original); err == nil {
		t.Fatal("session-only native owner obtained MFA preparation")
	}
	if got, err := (Work{}).MagicLinkMFAChallenge(owner); err == nil || got != (MFAContinuationPlan{}) {
		t.Fatal("zero invocation obtained challenge custody")
	}
}

func (p *magicLinkMFAValidationParticipant) ValidateMagicLinkMFAChallenge(c identity.Command, m MFAContinuationPlan) error {
	if c != p.expected || m != p.challenge {
		return invalidPlan()
	}
	return nil
}

func TestMagicLinkMFARequiresNativeOriginalScopeValidation(t *testing.T) {
	b, p := magicLinkMFAPlanFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}})
	owner := &magicLinkMFAValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{expected: command, proof: *p.Capability}, challenge: *p.MFAContinuation}
	if err := validateMagicLinkConsumption(owner, command, p); err != nil {
		t.Fatal("original native challenge rejected", err)
	}
	changed := p
	changed.MFAContinuation = cloneMFAContinuationPlan(p.MFAContinuation)
	changed.MFAContinuation.ScopeDigest[0]++
	if err := validateMagicLinkConsumption(owner, command, changed); err == nil {
		t.Fatal("primary proof validation silently accepted a different MFA scope")
	}
	if err := validateMagicLinkConsumption(&owner.magicLinkPreparationParticipant, command, p); err == nil {
		t.Fatal("session-only owner accepted challenge-only scope")
	}
}
