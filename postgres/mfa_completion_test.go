package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Local phase-custody oracle only, not a factor verifier or durable MFA store.
type mfaCompletionValidationParticipant struct {
	magicLinkPreparationParticipant
	completion MFACompletionPlan
}

func (*mfaCompletionValidationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *mfaCompletionValidationParticipant) ValidateMFACompletion(c identity.Command, proof CapabilityPlan, scope MFACompletionPlan) error {
	if c != p.expected || proof != p.proof || scope != p.completion {
		return invalidPlan()
	}
	return nil
}

func TestMFACompletionCustodyRequiresProtectedConsumedInvocation(t *testing.T) {
	b, p := mfaCompletionPlanFixture(t, "totp-verify")
	owner := &mfaCompletionValidationParticipant{}
	for _, mode := range []string{"current", "before consumption", "finalized", "returned", "commit", "foreign", "missing scope", "wrong child", "closed"} {
		t.Run(mode, func(t *testing.T) {
			frozen := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, capability: p.Capability, mfaCompletion: cloneMFACompletionPlan(p.MFACompletion)}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, mfaConsumed: true, execution: &domainExecution{reservation: &reservationState{plan: frozen, journal: journalReservation{generation: 1}}}}}
			candidate := owner
			switch mode {
			case "before consumption":
				w.state.mfaConsumed = false
			case "finalized":
				w.state.mfaFinalized = true
			case "returned":
				w.state.featureInvocation = nil
			case "commit":
				w.state.featureApplying = false
			case "foreign":
				candidate = &mfaCompletionValidationParticipant{}
			case "missing scope":
				frozen.mfaCompletion = nil
			case "wrong child":
				proof := *p.Capability
				proof.Purpose = "identity.magic-link.consume"
				frozen.capability = &proof
			case "closed":
				w.state.closed = true
			}
			binding, scope, err := w.MFACompletionConsumption(candidate)
			if mode != "current" {
				if err == nil || binding != (CapabilityReservationBinding{}) || scope != (MFACompletionPlan{}) {
					t.Fatal("unowned phase acquired MFA consumption")
				}
				return
			}
			if err != nil || scope != *p.MFACompletion || binding.Plan != *p.Capability || binding.Command != b {
				t.Fatal("lost original completion custody", err)
			}
			scope.ScopeDigest[0]++
			if frozen.mfaCompletion.ScopeDigest != p.MFACompletion.ScopeDigest {
				t.Fatal("borrowed projection mutated scope")
			}
		})
	}
}

func TestMFACompletionPreparationRequiresNativeScopeAndConservesVersions(t *testing.T) {
	for _, method := range []string{"totp-verify", "otp-verify"} {
		t.Run(method, func(t *testing.T) { testMFACompletionPreparation(t, method) })
	}
}

func testMFACompletionPreparation(t *testing.T, method string) {
	c, _, _ := coordinatorFixture(t)
	b, p := mfaCompletionPlanFixture(t, method)
	op := p.Feature.Operation
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}})
	if method == "otp-verify" {
		spec, _ := command.Feature()
		command = codeCodecCommand(t, spec, "123456")
	}
	owner := &mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, expected: command, proof: *p.Capability}, completion: *p.MFACompletion}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}}
	if method == "otp-verify" {
		entries = append(entries[:len(entries)-1:len(entries)-1], &otpReservationProbe{}, entries[len(entries)-1])
	}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	p.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := c.PrepareFeaturePreparationPlan(command, p)
	if err != nil {
		t.Fatal("native MFA session preparation unavailable", err)
	}
	_, admitted, _, err := c.prepareFeaturePreparation(command, prepared)
	if err != nil || admitted.mfaCompletion == nil || *admitted.mfaCompletion != owner.completion {
		t.Fatal("original completion dropped", err)
	}
	if !preparationFinalDeclaration(b, prepared, prepared) {
		t.Fatal("unchanged completion cannot be restored")
	}
	for _, mutate := range []func(*MFACompletionPlan){func(p *MFACompletionPlan) { p.ScopeDigest[0]++ }, func(p *MFACompletionPlan) { p.ContinuationVersion++ }, func(p *MFACompletionPlan) { p.FactorVersion++ }} {
		bad := prepared
		bad.MFACompletion = cloneMFACompletionPlan(prepared.MFACompletion)
		mutate(bad.MFACompletion)
		if _, err := c.PrepareFeaturePreparationPlan(command, bad); err == nil {
			t.Fatal("preparation accepted substituted original MFA scope")
		}
		if preparationFinalDeclaration(b, prepared, bad) {
			t.Fatal("restoration replaced completion scope")
		}
	}
	if _, _, _, err := c.prepareRestoredFeature(b, command, prepared); err != nil {
		t.Fatal("native completion execution unavailable", err)
	}
	if method == "otp-verify" {
		if _, err := c.PrepareCommandPlan(b, command, prepared); err == nil {
			t.Fatal("ordinary preparation admitted opaque OTP custody")
		}
	}
}
