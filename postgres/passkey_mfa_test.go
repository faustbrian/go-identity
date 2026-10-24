package postgres

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// Pure coordinator admission probes: these are not WebAuthn verification,
// factor verification, a durable continuation or session-producing workflows.
type passkeyMFAValidationParticipant struct {
	outputPreparationParticipant
	expected  identity.Command
	challenge MFAContinuationPlan
}

func (*passkeyMFAValidationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeyMFAValidationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (p *passkeyMFAValidationParticipant) ValidatePasskeyMFAChallenge(c identity.Command, m MFAContinuationPlan) error {
	if c != p.expected || m != p.challenge {
		return invalidPlan()
	}
	return nil
}

func TestPasskeyMFAPreparationRequiresOriginalOwnerAndBrowser(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, final := passkeyMFAPlanFixture(t)
	spec := identity.FeatureCommandSpec{Binding: b, Operation: final.Feature.Operation}
	command, err := identity.NewFeaturePreAuthCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	owner := &passkeyMFAValidationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{final.Feature.Operation}}}, expected: command, challenge: *final.MFAContinuation}
	registry, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{final.Contributors[1]}}, &riskPassiveProbe{registryContributor{final.Contributors[2]}}, owner, &issuancePlanProbe{}})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	final.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", final.Audits[0].EventType, final.SubjectType, b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	final.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, final.Feature.Operation, final.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	prepared, err := c.PrepareFeaturePreparationPlan(command, original)
	if err != nil {
		t.Fatal("passkey owner cannot prepare challenge-only original scope", err)
	}
	if _, admitted, _, err := c.prepareFeaturePreparation(command, prepared); err != nil || admitted == nil || admitted.capability != nil || admitted.mfaContinuation == nil {
		t.Fatal("original passkey challenge admission lost", err)
	}
	if err := validateMFAContinuation(owner, command, final); err != nil {
		t.Fatal("original passkey/browser custody denied", err)
	}
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	owner.expected = plain
	if err := validateFeatureCommand(owner, plain, final); err == nil {
		t.Fatal("structural command replaced original browser custody")
	}
	foreign := &verificationMFAValidationParticipant{expected: command, challenge: *final.MFAContinuation}
	if err := validateMFAContinuation(foreign, command, final); err == nil {
		t.Fatal("verification owner replaced original passkey owner")
	}
}

func TestPasskeyMFAChallengeRequiresExactProtectedInvocation(t *testing.T) {
	for _, mode := range []string{"current", "foreign", "returned", "preparation", "closed", "generation mismatch", "missing challenge", "missing child", "synthetic primary", "foreign record", "foreign origin"} {
		t.Run(mode, func(t *testing.T) {
			b, p := passkeyMFAPlanFixture(t)
			owner := &passkeyMFAValidationParticipant{}
			frozen := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, mfaContinuation: cloneMFAContinuationPlan(p.MFAContinuation), issuance: cloneCapabilityIssuancePlan(p.CapabilityIssuance), subjectType: p.SubjectType}
			for _, d := range p.Contributors {
				frozen.contributors = append(frozen.contributors, registeredContributor{descriptor: d})
			}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, execution: &domainExecution{reservation: &reservationState{plan: frozen, journal: journalReservation{generation: 1}}}}}
			candidate := owner
			switch mode {
			case "foreign":
				candidate = &passkeyMFAValidationParticipant{}
			case "returned":
				w.state.featureInvocation = nil
			case "preparation":
				w.state.featureApplying = false
			case "closed":
				w.state.closed = true
			case "generation mismatch":
				w.state.generation++
			case "missing challenge":
				frozen.mfaContinuation = nil
			case "missing child":
				frozen.issuance = nil
			case "synthetic primary":
				frozen.capability = &CapabilityPlan{}
			case "foreign record":
				frozen.binding.RecordID = "AgICAgICAgICAgICAgICAg"
				w.state.binding = frozen.binding
			case "foreign origin":
				frozen.feature.Operation.Owner = "identity/password"
			}
			got, err := w.PasskeyMFAChallenge(candidate)
			if mode != "current" {
				if err == nil || got != (MFAContinuationPlan{}) {
					t.Fatal("foreign or unusable invocation acquired original challenge")
				}
				return
			}
			if err != nil || got != *p.MFAContinuation {
				t.Fatal("original passkey scope lost", err)
			}
			copy := got
			copy.ScopeDigest[0]++
			if frozen.mfaContinuation.ScopeDigest != got.ScopeDigest {
				t.Fatal("returned scope mutated frozen original")
			}
			w.state.issuance = &workIssuance{plan: cloneCapabilityIssuancePlan(p.CapabilityIssuance)}
			payload := capability.Payload{ID: string(got.ID), Subject: string(got.UserID), Tenant: string(b.TenantID), Operation: "identity.mfa.complete", Resource: "mfa/continuations/" + string(got.ID), CorrelationID: string(b.CommandID), IssuedAt: got.IssuedAt, NotBefore: got.IssuedAt, ExpiresAt: got.ExpiresAt, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(got.ScopeDigest[:])}}
			if subject, err := magicLinkMFAIssuanceSubject(w, payload); err != nil || subject != b.UserID {
				t.Fatal("original passkey child cannot be staged", err)
			}
			payload.CorrelationID = "AgICAgICAgICAgICAgICAg"
			if subject, err := magicLinkMFAIssuanceSubject(w, payload); err == nil || subject != "" {
				t.Fatal("child selected a different passkey primary")
			}
			r := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{descriptor: owner.Descriptor(), contributor: owner}, plan: frozen, active: true}}
			if got, err := r.PasskeyMFAChallenge(owner); err != nil || got != *p.MFAContinuation {
				t.Fatal("recovery lost original passkey scope", err)
			}
			if got, err := r.PasskeyMFAChallenge(&passkeyMFAValidationParticipant{}); err == nil || got != (MFAContinuationPlan{}) {
				t.Fatal("foreign recovery owner acquired original scope")
			}
			r.state.active = false
			if got, err := r.PasskeyMFAChallenge(owner); err == nil || got != (MFAContinuationPlan{}) {
				t.Fatal("returned recovery owner acquired original scope")
			}
		})
	}
}
