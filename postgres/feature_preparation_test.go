package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	"testing"
	"time"
)

func TestPreparedFeatureRejectsUnownedInputs(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			result, err := c.ExecutePreparedFeature(ctx, identity.Command{}, CommandPlan{})
			if err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("unowned preparation executed")
			}
		}
	}
}

func TestPreparedManagedEmailAddsOnlyOriginalUserIssuanceAndDelivery(t *testing.T) {
	_, _, base := featurePlanFixture(t)
	b := codecBinding()
	b.ActorID = identity.ActorID(b.UserID)
	b.OperationID = "identity.email.verification-send"
	b.SchemaID = b.OperationID + ".native-v1"
	b.RecordID = "managed-email"
	base.SubjectType = "identifier"
	base.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/email", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
	base.Contributors[3] = base.Feature.Contributor
	base.Lifecycle = &LifecyclePlan{EventType: "identifier.attached.v1", BeforeVersion: 0, AfterVersion: 1}
	base.Audits[0].RetentionClass = "protected"
	final := base
	final.CapabilityIssuance = issuanceTestPlan()
	final.Delivery = deliveryTestPlan()
	final.Delivery.Intents[0].SubjectID = string(b.UserID)
	final.Delivery.Intents[0].Purpose = "identity.email.verification-request"
	final.Delivery.Intents[0].ExpiresAt = final.CapabilityIssuance.Grants[0].ExpiresAt
	final.Contributors = append(append([]ContributorDescriptor(nil), base.Contributors...), final.CapabilityIssuance.Contributor, final.Delivery.Contributor)
	if !preparationFinalDeclaration(b, base, final) {
		t.Fatal("original authenticated email cannot retain generated issuance/delivery")
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"signup-recipient":     func(p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "another-user" },
		"reset-recipient":      func(p *CommandPlan) { p.CapabilityIssuance.ResetRecipientUserID = "another-user" },
		"magic-link-recipient": func(p *CommandPlan) { p.CapabilityIssuance.MagicLinkRecipientUserID = "another-user" },
		"mfa-recipient":        func(p *CommandPlan) { p.CapabilityIssuance.MFAContinuationUserID = "another-user" },
		"different-purpose":    func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete" },
		"missing-delivery":     func(p *CommandPlan) { p.Delivery = nil; p.Contributors = p.Contributors[:len(p.Contributors)-1] },
		"additional-grant": func(p *CommandPlan) {
			g := p.CapabilityIssuance.Grants[0]
			g.CapabilityID = "other-grant"
			g.ReplayDigest[0]++
			g.ProofFingerprint[0]++
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, g)
		},
		"recipient-expansion": func(p *CommandPlan) { p.Delivery.Intents = append(p.Delivery.Intents, p.Delivery.Intents[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := final
			changed.CapabilityIssuance = cloneCapabilityIssuancePlan(final.CapabilityIssuance)
			changed.Delivery = cloneDeliveryPlan(final.Delivery)
			changed.Contributors = append([]ContributorDescriptor(nil), final.Contributors...)
			mutate(&changed)
			if preparationFinalDeclaration(b, base, changed) {
				t.Fatal("managed preparation widened its original recipient/profile")
			}
		})
	}
	foreign := b
	foreign.ActorID = "another-human"
	if preparationFinalDeclaration(foreign, base, final) {
		t.Fatal("another actor selected command-user issuance")
	}
	foreign = b
	foreign.UserID = ""
	if preparationFinalDeclaration(foreign, base, final) {
		t.Fatal("missing original user selected issuance")
	}
	_, command, unrelated := featurePlanFixture(t)
	spec, _ := command.Feature()
	unrelatedFinal := unrelated
	unrelatedFinal.CapabilityIssuance = issuanceTestPlan()
	unrelatedFinal.Delivery = deliveryTestPlan()
	unrelatedFinal.Contributors = append(append([]ContributorDescriptor(nil), unrelated.Contributors...), unrelatedFinal.CapabilityIssuance.Contributor, unrelatedFinal.Delivery.Contributor)
	if preparationFinalDeclaration(spec.Binding, unrelated, unrelatedFinal) {
		t.Fatal("unrelated feature gained authenticated issuance")
	}
}

func TestPreparationMagicLinkConservesOriginalConsumption(t *testing.T) {
	b, original := magicLinkConsumptionPlanFixture(t)
	if preparationProtected(original) || !preparationFinalDeclaration(b, original, original) {
		t.Fatal("closed magic-link consumption cannot retain its original preparation")
	}
	for name, change := range map[string]func(*CommandPlan){
		"removed-proof":   func(p *CommandPlan) { p.Capability = nil },
		"changed-proof":   func(p *CommandPlan) { p.Capability.ProofFingerprint[0]++ },
		"renewed-expiry":  func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		"changed-counter": func(p *CommandPlan) { p.CommandCounters.Fingerprint[0]++ },
		"removed-counter": func(p *CommandPlan) { p.CommandCounters = nil },
		"added-issuance":  func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"added-delivery":  func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"foreign-purpose": func(p *CommandPlan) { p.Capability.Purpose = "identity.identifier.verify" },
	} {
		t.Run(name, func(t *testing.T) {
			final := original
			proof, counters := *original.Capability, *original.CommandCounters
			final.Capability, final.CommandCounters = &proof, &counters
			change(&final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("generated session changed original consumption or charge")
			}
		})
	}
}

func TestPreparationMagicLinkConservesRegistration(t *testing.T) {
	b, signin := magicLinkConsumptionPlanFixture(t)
	signup := signin
	signup.MagicLinkRegistration = &MagicLinkRegistrationPlan{
		UserID: "prospective-user", IdentifierID: "prospective-email",
		CreationDigest: [32]byte{1}, EmailPossessionPolicyVersion: 3,
		CreationEventIndex: 1,
	}
	for name, original := range map[string]CommandPlan{"signin": signin, "signup": signup} {
		t.Run(name+"-unchanged", func(t *testing.T) {
			final := original
			final.MagicLinkRegistration = cloneMagicLinkRegistrationPlan(original.MagicLinkRegistration)
			if !preparationFinalDeclaration(b, original, final) {
				t.Fatal("unchanged original registration custody rejected")
			}
		})
	}
	t.Run("added", func(t *testing.T) {
		if preparationFinalDeclaration(b, signin, signup) {
			t.Fatal("restoration introduced signup into signin")
		}
	})
	t.Run("removed", func(t *testing.T) {
		if preparationFinalDeclaration(b, signup, signin) {
			t.Fatal("restoration removed original signup")
		}
	})
	for name, change := range map[string]func(*MagicLinkRegistrationPlan){
		"user":       func(p *MagicLinkRegistrationPlan) { p.UserID = "different-user" },
		"identifier": func(p *MagicLinkRegistrationPlan) { p.IdentifierID = "different-email" },
		"creation":   func(p *MagicLinkRegistrationPlan) { p.CreationDigest[0]++ },
		"policy":     func(p *MagicLinkRegistrationPlan) { p.EmailPossessionPolicyVersion++ },
		"event":      func(p *MagicLinkRegistrationPlan) { p.CreationEventIndex++ },
	} {
		t.Run(name, func(t *testing.T) {
			final := signup
			final.MagicLinkRegistration = cloneMagicLinkRegistrationPlan(signup.MagicLinkRegistration)
			change(final.MagicLinkRegistration)
			if preparationFinalDeclaration(b, signup, final) {
				t.Fatal("restoration changed original signup declaration")
			}
		})
	}
}

// This participant proves the public preparation-selection boundary only.
// It does not authenticate a browser/grant or implement durable login effects.
type magicLinkPreparationParticipant struct {
	outputPreparationParticipant
	expected identity.Command
	proof    CapabilityPlan
}

func (*magicLinkPreparationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}
func (p *magicLinkPreparationParticipant) ValidateFeaturePreparation(c identity.Command, plan CommandPlan) error {
	if c != p.expected || !consumptionAuthenticationPreparation(plan) || *plan.Capability != p.proof {
		return invalidPreparation()
	}
	return nil
}
func (p *magicLinkPreparationParticipant) ValidateMagicLinkConsumption(c identity.Command, proof CapabilityPlan) error {
	if c != p.expected || proof != p.proof {
		return invalidPlan()
	}
	return nil
}
func (*magicLinkPreparationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

type magicLinkPreparationCounter struct{ commandCounterProbe }

func (*magicLinkPreparationCounter) CheckCommandCounters(context.Context, CommandCounterAdmissionWork) error {
	return invalidWork()
}

type magicLinkAdmissionPreparationParticipant struct {
	*magicLinkPreparationParticipant
}

func (*magicLinkAdmissionPreparationParticipant) PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}
func (*magicLinkAdmissionPreparationParticipant) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

func TestPreparedMagicLinkSelectsOriginalClosedOwner(t *testing.T) {
	for _, counters := range []bool{true, false} {
		t.Run(map[bool]string{true: "historical-counters", false: "authentication-admission"}[counters], func(t *testing.T) {
			c, _, _ := coordinatorFixture(t)
			b, plan := magicLinkConsumptionPlanFixture(t)
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: []identity.FeatureField{{Name: "original", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-request"}}}})
			owner := &magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{magicLinkConsumeOperation()}}}, expected: command, proof: *plan.Capability}
			var participant Contributor = owner
			if !counters {
				participant = &magicLinkAdmissionPreparationParticipant{owner}
				plan.CommandCounters = nil
			}
			entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, participant}
			if counters {
				entries = append(entries, &magicLinkPreparationCounter{})
			}
			entries = append(entries, &capabilityExecutionProbe{})
			registry, err := NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			c.registry = registry
			plan.Contributors = registry.Descriptors()
			seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, magicLinkConsumeOperation(), plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := c.PrepareFeaturePreparationPlan(command, plan)
			if err != nil || prepared.Digest == ([32]byte{}) || prepared.Capability == nil || *prepared.Capability != owner.proof {
				t.Fatal("original consuming input cannot use native preparation", err)
			}
			_, admitted, selected, err := c.prepareFeaturePreparation(command, prepared)
			if err != nil || admitted == nil || selected != participant || admitted.binding != b {
				t.Fatal("preparation changed registered consumption ownership", err)
			}
			if !counters {
				entries[3] = owner
				withoutAdmission, e := NewContributorRegistry(entries)
				if e != nil {
					t.Fatal(e)
				}
				c.registry = withoutAdmission
				if _, err := c.PrepareFeaturePreparationPlan(command, prepared); err == nil {
					t.Fatal("counter-free consumption admitted an owner without retained admission")
				}
				c.registry = registry
			}
			prepared.Capability.ExpiresAt = prepared.Capability.ExpiresAt.Add(time.Second)
			if _, err := c.PrepareFeaturePreparationPlan(command, prepared); err == nil {
				t.Fatal("preparation renewed original proof expiry")
			}
		})
	}
}

func TestMagicLinkAdmissionCannotExecuteWithoutRetainedCustody(t *testing.T) {
	w, _ := preparationOutputFixture(t)
	c := w.state.execution.coordinator
	w.state.execution.reservation.plan.feature.Operation = magicLinkConsumeOperation()
	w.state.execution.reservation.plan.counters = nil
	if err := c.checkPreparedAdmission(w); err == nil {
		t.Fatal("counter-free magic-link consumption executed without original admission")
	}
	w.state.execution.reservation.preparation = nil
	if err := c.checkPreparedAdmission(w); err == nil {
		t.Fatal("ordinary execution bypassed magic-link authentication preparation")
	}
}

func TestPreparationFinalDeclarationConservesCounterScope(t *testing.T) {
	_, _, plan := featurePlanFixture(t)
	plan.SubjectType = "session"
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
	if !preparationFinalDeclaration(codecBinding(), plan, plan) {
		t.Fatal("matching counter declaration rejected")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion++ },
		func(p *CommandPlan) { p.CommandCounters.Fingerprint[0]++ },
		func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
	} {
		final := plan
		counter := *plan.CommandCounters
		final.CommandCounters = &counter
		change(&final)
		if preparationFinalDeclaration(codecBinding(), plan, final) {
			t.Fatal("final plan changed protected scope")
		}
	}
	without := plan
	without.CommandCounters = nil
	if preparationFinalDeclaration(codecBinding(), without, plan) {
		t.Fatal("generated plan introduced an uncharged counter")
	}
}

func TestPreparationFinalDeclarationAllowsSignupVerificationIssuance(t *testing.T) {
	b, original, final := signupPreparationPlanFixture(t)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("original prepared signup cannot enlist generated verification issuance")
	}
	if !preparationProtected(final) {
		t.Fatal("issuance entered the original admission declaration")
	}
	final.Delivery = deliveryTestPlan()
	final.Contributors = append(final.Contributors, final.Delivery.Contributor)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("original verification issuance cannot enlist delivery")
	}
}

func signupPreparationPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	_, _, original := featurePlanFixture(t)
	original.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
	original.Contributors[3] = original.Feature.Contributor
	original.SubjectType, original.Lifecycle = "user", &LifecyclePlan{EventType: "user.created.v1"}
	final := original
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.RegistrationUserID = "new-user"
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor)
	b := codecBinding()
	b.UserID, b.AnonymousFlowID, b.RecordID = "", string(b.CommandID), ""
	b.OperationID, b.SchemaID, b.SchemaVersion = original.Feature.Operation.OperationID, original.Feature.Operation.SchemaID, original.Feature.Operation.SchemaVersion
	return b, original, final
}

func TestPreparationSignupIssuanceDoesNotBroadenProtectedProfiles(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"missing-target":     func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "" },
		"authenticated-user": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "new-user" },
		"missing-flow":       func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"non-verification": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.attach"
		},
		"invalid-grant":  func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.Grants[0].MaxUses = 2 },
		"consumption":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"identifier":     func(_ *identity.CommandBinding, p *CommandPlan) { p.IdentifierAdmission = &ContributorDescriptor{} },
		"otp":            func(_ *identity.CommandBinding, p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		"risk":           func(_ *identity.CommandBinding, p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		"captcha":        func(_ *identity.CommandBinding, p *CommandPlan) { p.CaptchaEvidence = &CaptchaEvidencePlan{} },
		"captcha-replay": func(_ *identity.CommandBinding, p *CommandPlan) { p.CaptchaReplayReservation = true },
		"foreign-owner":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "foreign" },
		"wrong-operation": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.signin"
		},
		"changed-lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "other.created.v1" },
		"changed-audit":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].BindingDigest[0]++ },
		"removed-base":      func(_ *identity.CommandBinding, p *CommandPlan) { p.Contributors = p.Contributors[1:] },
		"reordered-base": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors[0], p.Contributors[1] = p.Contributors[1], p.Contributors[0]
		},
		"duplicate-issuer": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
		},
		"unknown-owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "foreign", ContractID: "foreign", Version: 1})
		},
		"delivery-before-issuer": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Delivery = deliveryTestPlan()
			p.Contributors[len(p.Contributors)-1] = p.Delivery.Contributor
			p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := signupPreparationPlanFixture(t)
			feature, lifecycle := *final.Feature, *final.Lifecycle
			final.Feature, final.Lifecycle = &feature, &lifecycle
			final.Audits = append([]AuditPlan(nil), final.Audits...)
			change(&b, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("generated issuance broadened original preparation authority")
			}
		})
	}
}
