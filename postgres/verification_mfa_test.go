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

// Tests only the coordinator's pure native-owner dispatch, not authentication.
type verificationMFAValidationParticipant struct {
	outputPreparationParticipant
	expected  identity.Command
	challenge MFAContinuationPlan
}

func (*verificationMFAValidationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (*verificationMFAValidationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (p *verificationMFAValidationParticipant) ValidateEmailVerificationMFAChallenge(c identity.Command, m MFAContinuationPlan) error {
	if c != p.expected || m != p.challenge {
		return invalidPlan()
	}
	return nil
}

func TestVerificationMFAPreparationRequiresOriginalClosedOwner(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, final := verificationMFAPlanFixture(t)
	spec := identity.FeatureCommandSpec{Binding: b, Operation: final.Feature.Operation}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	command, err := identity.NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	owner := &verificationMFAValidationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{final.Feature.Operation}}}, expected: command, challenge: *final.MFAContinuation}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{final.Contributors[1]}}, &riskPassiveProbe{registryContributor{final.Contributors[2]}}, owner, &issuancePlanProbe{}}
	registry, err := NewContributorRegistry(entries)
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
		t.Fatal("verification owner cannot prepare challenge without synthetic consumption", err)
	}
	if _, admitted, _, err := c.prepareFeaturePreparation(command, prepared); err != nil || admitted == nil || admitted.capability != nil || admitted.mfaContinuation == nil {
		t.Fatal("verification challenge admission lost", err)
	}
	if err := validateMFAContinuation(owner, command, final); err != nil {
		t.Fatal("original verification owner/custody rejected", err)
	}
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	owner.expected = plain
	if err := validateFeatureCommand(owner, plain, final); err == nil {
		t.Fatal("structural command substituted for original browser custody")
	}
	owner.expected = command
	foreign := &passwordMFAValidationParticipant{expected: command, challenge: *final.MFAContinuation}
	if err := validateMFAContinuation(foreign, command, final); err == nil {
		t.Fatal("password owner substituted for committed verification owner")
	}
}

func TestVerificationMFAChallengeRequiresExactProtectedInvocation(t *testing.T) {
	for _, mode := range []string{"current", "foreign", "returned", "preparation", "closed", "generation mismatch", "missing challenge", "missing child", "synthetic primary", "self parent", "foreign origin"} {
		t.Run(mode, func(t *testing.T) {
			b, p := verificationMFAPlanFixture(t)
			owner := &verificationMFAValidationParticipant{}
			frozen := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, mfaContinuation: cloneMFAContinuationPlan(p.MFAContinuation), issuance: cloneCapabilityIssuancePlan(p.CapabilityIssuance), subjectType: p.SubjectType}
			for _, d := range p.Contributors {
				frozen.contributors = append(frozen.contributors, registeredContributor{descriptor: d})
			}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, execution: &domainExecution{reservation: reservation}}}
			candidate := owner
			switch mode {
			case "foreign":
				candidate = &verificationMFAValidationParticipant{}
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
			case "self parent":
				frozen.binding.RecordID = string(b.CommandID)
				w.state.binding = frozen.binding
			case "foreign origin":
				frozen.feature.Operation.Owner = "identity/password"
			}
			got, err := w.EmailVerificationMFAChallenge(candidate)
			if mode != "current" {
				if err == nil || got != (MFAContinuationPlan{}) {
					t.Fatal("foreign or unusable invocation acquired challenge")
				}
				return
			}
			if err != nil || got != *p.MFAContinuation {
				t.Fatal("original verification challenge lost", err)
			}
			got.ScopeDigest[0]++
			if frozen.mfaContinuation.ScopeDigest != p.MFAContinuation.ScopeDigest {
				t.Fatal("projection mutated frozen original scope")
			}
			w.state.issuance = &workIssuance{plan: cloneCapabilityIssuancePlan(p.CapabilityIssuance)}
			payload := capability.Payload{ID: string(got.ID), Subject: string(got.UserID), Tenant: string(b.TenantID), Operation: "identity.mfa.complete", Resource: "mfa/continuations/" + string(got.ID), CorrelationID: b.RecordID, IssuedAt: p.MFAContinuation.IssuedAt, NotBefore: p.MFAContinuation.IssuedAt, ExpiresAt: p.MFAContinuation.ExpiresAt, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(p.MFAContinuation.ScopeDigest[:])}}
			if subject, err := magicLinkMFAIssuanceSubject(w, payload); err != nil || subject != b.UserID {
				t.Fatal("original verification child cannot be staged", err)
			}
			payload.CorrelationID = "AwMDAwMDAwMDAwMDAwMDAw"
			if subject, err := magicLinkMFAIssuanceSubject(w, payload); err == nil || subject != "" {
				t.Fatal("signed child selected a foreign verification parent")
			}
			r := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{descriptor: owner.Descriptor(), contributor: owner}, plan: frozen, active: true}}
			recovered, err := r.EmailVerificationMFAChallenge(owner)
			if err != nil || recovered != *p.MFAContinuation {
				t.Fatal("recovery lost unchanged original scope", err)
			}
			if got, err := r.EmailVerificationMFAChallenge(&verificationMFAValidationParticipant{}); err == nil || got != (MFAContinuationPlan{}) {
				t.Fatal("foreign recovery owner admitted")
			}
			r.state.active = false
			if got, err := r.EmailVerificationMFAChallenge(owner); err == nil || got != (MFAContinuationPlan{}) {
				t.Fatal("returned recovery owner admitted")
			}
		})
	}
}
