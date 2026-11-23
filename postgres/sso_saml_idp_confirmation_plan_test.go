package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func samlIDPConfirmationPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	binding, plan := samlSigninPlanFixture(t)
	operation := identity.FeatureOperation{
		Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", SchemaID: "sso-enterprise-saml-idp-init-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser,
	}
	binding.OperationID, binding.SchemaID = operation.OperationID, operation.SchemaID
	binding.UserID, binding.AnonymousFlowID, binding.RecordID = "linked-user", "", "pending-confirmation"
	plan.Feature.Operation = operation
	plan.Feature.Contributor = ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}
	plan.Contributors[3] = plan.Feature.Contributor
	plan.SubjectType = "sso_saml_confirmation"
	plan.Capability.Purpose = "identity.sso.saml-idp-init"
	return binding, plan
}

func samlIDPConfirmationCommand(t *testing.T, binding identity.CommandBinding, operation identity.FeatureOperation) identity.Command {
	t.Helper()
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	synchronizer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	command, err := identity.NewFeatureSAMLIDPConfirmationCommand(
		identity.FeatureCommandSpec{Binding: binding, Operation: operation},
		authentication.NewBearerCredential(cookie), authentication.NewBearerCredential(synchronizer),
	)
	if err != nil {
		t.Fatal("retain joint browser confirmation custody", err)
	}
	return command
}

type samlIDPConfirmationParticipant struct {
	outputPreparationParticipant
	original identity.Command
	proof    CapabilityPlan
}

var _ SSOSAMLIDPConfirmationContributor = (*samlIDPConfirmationParticipant)(nil)

func (*samlIDPConfirmationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}
}

func (p *samlIDPConfirmationParticipant) ValidateSSOSAMLIDPConfirmationConsumption(command identity.Command, proof CapabilityPlan) error {
	if command != p.original || proof != p.proof {
		return invalidPlan()
	}
	return nil
}

func (*samlIDPConfirmationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func (*samlIDPConfirmationParticipant) PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

func (*samlIDPConfirmationParticipant) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

func samlIDPConfirmationPreparationFixture(t *testing.T) (*Coordinator, identity.CommandBinding, CommandPlan, identity.Command, *samlIDPConfirmationParticipant) {
	t.Helper()
	binding, plan := samlIDPConfirmationPlanFixture(t)
	command := samlIDPConfirmationCommand(t, binding, plan.Feature.Operation)
	owner := &samlIDPConfirmationParticipant{
		outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}},
		original:                     command,
		proof:                        *plan.Capability,
	}
	coordinator, _, _ := coordinatorFixture(t)
	registry, err := NewContributorRegistry([]Contributor{
		&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}},
		&riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner, &capabilityExecutionProbe{},
	})
	if err != nil {
		t.Fatal("enroll native confirmation owner and one-use participant", err)
	}
	coordinator.registry = registry
	plan.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), binding, 1, 2, time.Unix(1800000000, 0).UTC(), "committed", plan.Audits[0].EventType, plan.SubjectType, binding.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(binding, plan.Feature.Operation, plan.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, binding, plan, command, owner
}

func TestSSOSAMLIDPConfirmationPlanRetainsExactLinkedUserAndOneUseProof(t *testing.T) {
	binding, plan := samlIDPConfirmationPlanFixture(t)
	if SSOSAMLIDPConfirmationOperation() != plan.Feature.Operation {
		t.Fatal("confirmation operation lost its exact user-targeted, record-required SAML identity")
	}
	fingerprint := [32]byte{19}
	wire, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("native confirmation could not enlist its original one-use proof", err)
	}
	restored, err := decodeFeaturePlan(binding, fingerprint, wire)
	if err != nil || restored.Digest != sha256.Sum256(wire) || restored.Feature == nil || *restored.Feature != *plan.Feature || restored.Capability == nil || *restored.Capability != *plan.Capability || restored.Lifecycle == nil || *restored.Lifecycle != (LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}) {
		t.Fatal("retained confirmation lost its native owner, proof or session transition", err)
	}
	again, err := encodeFeaturePlan(binding, fingerprint, restored)
	if err != nil || !bytes.Equal(wire, again) || !preparationFinalDeclaration(binding, plan, restored) {
		t.Fatal("confirmation changed during preparation restoration", err)
	}
	changed := *restored.Capability
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
	restored.Capability = &changed
	if preparationFinalDeclaration(binding, plan, restored) {
		t.Fatal("restoration renewed the original pending confirmation deadline")
	}
	spBinding, spPlan := samlSigninPlanFixture(t)
	if _, err := decodeFeaturePlan(spBinding, fingerprint, wire); err == nil {
		t.Fatal("SP-initiated ACS restored an unsolicited confirmation")
	}
	spWire, err := encodeFeaturePlan(spBinding, fingerprint, spPlan)
	if err != nil {
		t.Fatal("SP callback control", err)
	}
	if _, err := decodeFeaturePlan(binding, fingerprint, spWire); err == nil {
		t.Fatal("IdP confirmation restored SP request correlation")
	}
}

func TestSSOSAMLIDPConfirmationPlanRejectsMissingAndSubstitutedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"missing proof": func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = nil },
		"SP proof":      func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.sso.saml-acs" },
		"multiple use":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		"missing capability participant": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors = p.Contributors[:len(p.Contributors)-1]
		},
		"foreign capability participant": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors[len(p.Contributors)-1].ContractID = "capability.foreign"
		},
		"missing user": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "" },
		"anonymous flow": func(b *identity.CommandBinding, _ *CommandPlan) {
			b.UserID, b.AnonymousFlowID = "", "AQEBAQEBAQEBAQEBAQEBAQ"
		},
		"user actor":     func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser },
		"missing record": func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "" },
		"SP owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "sso.saml-login-callback"
		},
		"foreign record type": func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "sso_login_transaction" },
		"foreign audit": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Audits[0].EventType = "identity.oauth.handle_callback"
		},
		"unprotected audit": func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "ordinary" },
		"foreign lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "sso.login.created.v1" },
		"wrong versions": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding, plan := samlIDPConfirmationPlanFixture(t)
			mutate(&binding, &plan)
			if _, err := encodeFeaturePlan(binding, [32]byte{19}, plan); err == nil {
				t.Fatal("incomplete or foreign confirmation authority was admitted")
			}
		})
	}
}

func TestSSOSAMLIDPConfirmationRegistryRejectsGenericOwnerAndSchemaAlias(t *testing.T) {
	_, plan := samlIDPConfirmationPlanFixture(t)
	for name, mutate := range map[string]func(*featureRegistryContributor){
		"generic SAML owner": func(p *featureRegistryContributor) {
			p.descriptor = ContributorDescriptor{Owner: "sso/saml/postgres", ContractID: "sso.saml", Version: 1}
		},
		"SP native owner": func(p *featureRegistryContributor) { p.descriptor = ssoSAMLSigninDescriptor() },
		"schema alias":    func(p *featureRegistryContributor) { p.operations[0].SchemaID = "generic-saml-confirmation" },
		"anonymous profile": func(p *featureRegistryContributor) {
			p.operations[0].SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
	} {
		t.Run(name, func(t *testing.T) {
			participant := &featureRegistryContributor{descriptor: plan.Feature.Contributor, operations: []identity.FeatureOperation{plan.Feature.Operation}}
			mutate(participant)
			if _, err := NewContributorRegistry([]Contributor{participant}); err == nil {
				t.Fatal("generic registration bypassed exact native confirmation ownership")
			}
		})
	}
}

func TestSSOSAMLIDPConfirmationOrdinaryReservationRejectsBeforeCoordinatorAccess(t *testing.T) {
	binding, plan := samlIDPConfirmationPlanFixture(t)
	command := samlIDPConfirmationCommand(t, binding, plan.Feature.Operation)
	var coordinator *Coordinator
	_, _, err := coordinator.ReserveCommand(t.Context(), binding, command, plan)
	if !errors.Is(err, invalidPlan()) {
		t.Fatal("ordinary reservation reached coordinator access with unprepared confirmation", err)
	}
}

func TestSSOSAMLIDPConfirmationPreparationRequiresJointCustodyAndExactNativeProof(t *testing.T) {
	coordinator, _, plan, command, owner := samlIDPConfirmationPreparationFixture(t)
	_, admitted, selected, err := coordinator.prepareFeaturePreparation(command, plan)
	if err != nil || admitted == nil || selected != owner || admitted.capability == nil || *admitted.capability != owner.proof {
		t.Fatal("native owner could not select the original confirmation proof", err)
	}
	spec, ok := command.SAMLIDPConfirmationFeature()
	if !ok {
		t.Fatal("confirmation fixture lost typed custody")
	}
	metadata, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	owner.original = metadata
	if _, _, _, err := coordinator.prepareFeaturePreparation(metadata, plan); err == nil {
		t.Fatal("metadata-only alias acquired confirmation admission")
	}
	owner.original = command
	owner.proof.ReplayDigest[0]++
	if _, _, _, err := coordinator.prepareFeaturePreparation(command, plan); err == nil {
		t.Fatal("native owner admitted another pending confirmation proof")
	}
	owner.proof = *plan.Capability
	spBinding, spPlan := samlSigninPlanFixture(t)
	spCommand := ssoOIDCAccountPreAuthCommand(t, identity.FeatureCommandSpec{Binding: spBinding, Operation: spPlan.Feature.Operation})
	owner.original = spCommand
	if _, _, _, err := coordinator.prepareFeaturePreparation(spCommand, plan); err == nil {
		t.Fatal("SP browser request custody replaced the independent confirmation")
	}
}

type samlIDPConfirmationSPParticipant struct{ samlPreparationParticipant }

func (*samlIDPConfirmationSPParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}
}

func TestSSOSAMLIDPConfirmationPreparationRejectsParticipantWithOnlySPConsumption(t *testing.T) {
	coordinator, _, plan, command, owner := samlIDPConfirmationPreparationFixture(t)
	spOnly := &samlIDPConfirmationSPParticipant{samlPreparationParticipant{
		outputPreparationParticipant: owner.outputPreparationParticipant, original: command, proof: owner.proof,
	}}
	registry, err := NewContributorRegistry([]Contributor{
		&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}},
		&riskPassiveProbe{registryContributor{plan.Contributors[2]}}, spOnly, &capabilityExecutionProbe{},
	})
	if err != nil {
		return
	}
	coordinator.registry = registry
	plan.Contributors = registry.Descriptors()
	if _, _, _, err := coordinator.prepareFeaturePreparation(command, plan); err == nil {
		t.Fatal("SP-only participant acquired independent confirmation admission")
	}
}

func TestSSOSAMLIDPConfirmationConsumptionIsProvisionalAndExactApplyOnly(t *testing.T) {
	coordinator, binding, plan, command, owner := samlIDPConfirmationPreparationFixture(t)
	_, admitted, _, err := coordinator.prepareFeaturePreparation(command, plan)
	if err != nil {
		t.Fatal("prepare original confirmation", err)
	}
	reservation := &reservationState{plan: admitted, journal: journalReservation{generation: 3}}
	state := &workState{
		ctx: t.Context(), binding: binding, generation: 3, feature: plan.Feature,
		lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true,
		execution: &domainExecution{reservation: reservation},
	}
	work := Work{state: state}
	if _, err := work.SSOSAMLIDPConfirmationConsumption(owner); err == nil {
		t.Fatal("Apply exposed confirmation before provisional one-use consumption")
	}
	state.oauthSigninStage = oauthSigninStateConsumed
	got, err := work.SSOSAMLIDPConfirmationConsumption(owner)
	if err != nil || got.Command != binding || got.Plan != owner.proof || got.Generation != 3 || got.Fingerprint != admitted.fingerprint {
		t.Fatal("exact native Apply lost original provisional confirmation consumption", err)
	}
	other := &samlIDPConfirmationParticipant{}
	if _, err := work.SSOSAMLIDPConfirmationConsumption(other); err == nil {
		t.Fatal("descriptor-equivalent foreign instance borrowed confirmation consumption")
	}
	if _, err := work.SSOSAMLSigninConsumption(owner); err == nil {
		t.Fatal("SP callback borrowed IdP confirmation consumption")
	}
	state.featureApplying = false
	if _, err := work.SSOSAMLIDPConfirmationConsumption(owner); err == nil {
		t.Fatal("confirmation consumption escaped synchronous Apply")
	}
	state.featureApplying = true
	state.oauthSigninStage = oauthSigninStateFinalized
	if _, err := work.SSOSAMLIDPConfirmationConsumption(owner); err == nil {
		t.Fatal("finalized consumption remained available as provisional Apply state")
	}
}
