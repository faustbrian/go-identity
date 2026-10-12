package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// A pure dispatch probe, not password comparison or a committable workflow.
type passwordMFAValidationParticipant struct {
	outputPreparationParticipant
	expected  identity.Command
	challenge MFAContinuationPlan
}

func (*passwordMFAValidationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*passwordMFAValidationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (p *passwordMFAValidationParticipant) ValidatePasswordMFAChallenge(c identity.Command, m MFAContinuationPlan) error {
	if c != p.expected || m != p.challenge {
		return invalidPlan()
	}
	return nil
}

func TestPasswordMFAPreparationRequiresOriginalClosedOwner(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, final := passwordMFAPlanFixture(t)
	command, secret := passwordSigninCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: final.Feature.Operation}, []byte("synthetic-password-primary"), base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	defer secret.Destroy()
	owner := &passwordMFAValidationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{final.Feature.Operation}}}, expected: command, challenge: *final.MFAContinuation}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{final.Contributors[1]}}, &riskPassiveProbe{registryContributor{final.Contributors[2]}}, owner, &issuancePlanProbe{}}
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
	final.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, final.Feature.Operation, final.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	prepared, err := c.PrepareFeaturePreparationPlan(command, original)
	if err != nil {
		t.Fatal("password owner cannot prepare challenge", err)
	}
	if _, admitted, _, err := c.prepareFeaturePreparation(command, prepared); err != nil || admitted == nil || admitted.capability != nil || admitted.mfaContinuation == nil {
		t.Fatal("original password challenge admission lost", err)
	}
}

func TestPasswordMFAChallengeScopeRequiresExactProtectedInvocation(t *testing.T) {
	for _, mode := range []string{"current", "foreign", "returned", "commit check", "closed", "generation mismatch", "missing challenge", "missing child", "synthetic primary"} {
		t.Run(mode, func(t *testing.T) {
			b, p := passwordMFAPlanFixture(t)
			owner := &passwordMFAValidationParticipant{}
			frozen := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, mfaContinuation: cloneMFAContinuationPlan(p.MFAContinuation), issuance: cloneCapabilityIssuancePlan(p.CapabilityIssuance), subjectType: p.SubjectType}
			for _, d := range p.Contributors {
				frozen.contributors = append(frozen.contributors, registeredContributor{descriptor: d})
			}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, execution: &domainExecution{reservation: reservation}}}
			candidate := owner
			switch mode {
			case "foreign":
				candidate = &passwordMFAValidationParticipant{}
			case "returned":
				w.state.featureInvocation = nil
			case "commit check":
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
			}
			got, err := w.PasswordMFAChallenge(candidate)
			if mode != "current" {
				if err == nil || got != (MFAContinuationPlan{}) {
					t.Fatal("foreign or unusable invocation acquired original challenge")
				}
				return
			}
			if err != nil || got != *p.MFAContinuation {
				t.Fatal("original password scope lost", err)
			}
			got.ScopeDigest[0]++
			if frozen.mfaContinuation.ScopeDigest != p.MFAContinuation.ScopeDigest {
				t.Fatal("projection mutated frozen scope")
			}
		})
	}
}
