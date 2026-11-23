package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type samlSigninAccountParticipant struct{ scopeFeatureParticipant }

func (*samlSigninAccountParticipant) Descriptor() ContributorDescriptor {
	return ssoSAMLSigninDescriptor()
}

func samlSigninAccountCommand(t *testing.T, expected ProviderAccountAdmission) (identity.FeatureCommandSpec, identity.Command) {
	t.Helper()
	binding, plan := samlSigninPlanFixture(t)
	binding.TenantID = expected.Account.TenantID
	fields, err := SSOSAMLSigninAccountFields(expected)
	if err != nil {
		t.Fatal("freeze original linked SAML account", err)
	}
	spec := identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation, Fields: fields}
	return spec, ssoOIDCAccountPreAuthCommand(t, spec)
}

func samlSigninPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	binding, plan := ssoOIDCSigninPlanFixture(t)
	op := identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-acs", SchemaID: "sso-enterprise-saml-acs-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	binding.OperationID, binding.SchemaID = op.OperationID, op.SchemaID
	plan.Feature.Operation = op
	plan.Feature.Contributor.ContractID = "sso.saml-login-callback"
	plan.Contributors[3] = plan.Feature.Contributor
	plan.Capability.Purpose = "identity.sso.saml-acs"
	return binding, plan
}

func TestSSOSAMLCallbackPlanBindsOneUseToOriginalStart(t *testing.T) {
	binding, plan := samlSigninPlanFixture(t)
	owner := &featureRegistryContributor{descriptor: plan.Feature.Contributor, operations: []identity.FeatureOperation{plan.Feature.Operation}}
	if _, err := NewContributorRegistry([]Contributor{owner}); err != nil {
		t.Fatal("could not select the exact SAML ACS owner", err)
	}
	fingerprint := [32]byte{13}
	encoded, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("native ACS did not admit its original one-use state", err)
	}
	decoded, err := decodeFeaturePlan(binding, fingerprint, encoded)
	if err != nil || decoded.Feature == nil || *decoded.Feature != *plan.Feature || decoded.Capability == nil || *decoded.Capability != *plan.Capability || !preparationFinalDeclaration(binding, plan, decoded) {
		t.Fatal("retained ACS declaration lost original capability, owner or lifecycle", err)
	}
	changed := *decoded.Capability
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
	decoded.Capability = &changed
	if preparationFinalDeclaration(binding, plan, decoded) {
		t.Fatal("restoration widened the original SAML expiry")
	}
	for _, sibling := range []func(*testing.T) (identity.CommandBinding, CommandPlan){ssoOIDCSigninPlanFixture, ssoOAuth2SigninPlanFixture} {
		other, otherPlan := sibling(t)
		if _, err := decodeFeaturePlan(other, fingerprint, encoded); err == nil {
			t.Fatal("sibling protocol restored the SAML declaration")
		}
		otherWire, err := encodeFeaturePlan(other, fingerprint, otherPlan)
		if err != nil {
			t.Fatal("sibling declaration control", err)
		}
		if _, err := decodeFeaturePlan(binding, fingerprint, otherWire); err == nil {
			t.Fatal("SAML restored another protocol's one-use state")
		}
	}
}

func TestSSOSAMLCallbackPlanRejectsGenericRegistrationAndUnboundProof(t *testing.T) {
	binding, plan := samlSigninPlanFixture(t)
	alias := plan.Feature.Operation
	alias.SchemaID = "generic-saml-acs"
	aliasOwner := &featureRegistryContributor{descriptor: ContributorDescriptor{Owner: "sso/saml/postgres", ContractID: "sso.saml", Version: 1}, operations: []identity.FeatureOperation{alias}}
	if _, err := NewContributorRegistry([]Contributor{aliasOwner}); err == nil {
		t.Fatal("generic owner bypassed mandatory SAML capability admission")
	}
	aliasOwner.descriptor = plan.Feature.Contributor
	if _, err := NewContributorRegistry([]Contributor{aliasOwner}); err == nil {
		t.Fatal("exact owner registered a different SAML ACS schema")
	}
	fingerprint := [32]byte{13}
	wrongStart := binding
	wrongStart.RecordID = string(binding.CommandID)
	if _, err := encodeFeaturePlan(wrongStart, fingerprint, plan); err == nil {
		t.Fatal("callback selected itself instead of the original start command")
	}
	otherProof := *plan.Capability
	otherProof.Purpose = "identity.sso.oauth-callback"
	foreign := plan
	foreign.Capability = &otherProof
	if _, err := encodeFeaturePlan(binding, fingerprint, foreign); err == nil {
		t.Fatal("another protocol's capability was accepted")
	}
	plan.Capability, plan.Contributors = nil, plan.Contributors[:4]
	if _, err := encodeFeaturePlan(binding, fingerprint, plan); err == nil {
		t.Fatal("SAML callback was accepted without the original proof")
	}
}

func TestSSOSAMLCallbackAccountSnapshotDoesNotAliasOtherProtocols(t *testing.T) {
	expected := ssoOIDCSigninAccountFixture()
	if _, err := SSOSAMLSigninAccountFields(expected); err == nil {
		t.Fatal("legacy account provider entered the SAML-only snapshot")
	}
	expected.Account.Provider = "sso.saml.v1." + strings.Repeat("a", 64)
	expected.Account.Issuer = "urn:example:trusted-saml-idp"
	spec, command := samlSigninAccountCommand(t, expected)
	if got, err := SSOSAMLSigninAccount(command); err != nil || got != expected {
		t.Fatal("original SAML account snapshot did not round-trip", err)
	}
	for _, other := range []func(identity.Command) (ProviderAccountAdmission, error){SSOOIDCSigninAccount, SSOOAuth2SigninAccount, OAuthSigninAccount} {
		if _, err := other(command); err == nil {
			t.Fatal("sibling account decoder admitted a SAML command")
		}
	}
	mixed := spec
	mixed.Fields = append(append([]identity.FeatureField(nil), spec.Fields...), identity.FeatureField{Name: ssoOAuth2SigninAccountPrefix + "user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other-user"}})
	if _, err := SSOSAMLSigninAccount(ssoOIDCAccountPreAuthCommand(t, mixed)); err == nil {
		t.Fatal("mixed protocol snapshot obtained SAML account admission")
	}
	metadata, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SSOSAMLSigninAccount(metadata); err == nil {
		t.Fatal("pure metadata obtained protected browser account snapshot")
	}
}

func TestSSOSAMLCallbackOrdinaryReservationRejectsBeforeCoordinatorAccess(t *testing.T) {
	binding, plan := samlSigninPlanFixture(t)
	var coordinator *Coordinator
	_, _, err := coordinator.ReserveCommand(context.Background(), binding, identity.Command{}, plan)
	if !errors.Is(err, invalidPlan()) {
		t.Fatal("unprepared SAML callback reached the ordinary coordinator", err)
	}
}

type samlPreparationParticipant struct {
	outputPreparationParticipant
	original identity.Command
	proof    CapabilityPlan
}

func (*samlPreparationParticipant) Descriptor() ContributorDescriptor {
	return ssoSAMLSigninDescriptor()
}
func (p *samlPreparationParticipant) ValidateSSOSAMLSigninConsumption(command identity.Command, proof CapabilityPlan) error {
	if command != p.original || proof != p.proof {
		return invalidPlan()
	}
	return nil
}
func (*samlPreparationParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (*samlPreparationParticipant) PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}
func (*samlPreparationParticipant) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

func TestSSOSAMLCallbackNativeOwnerSelectsOriginalPreparationAndApplyConsumption(t *testing.T) {
	b, plan := samlSigninPlanFixture(t)
	command := ssoOIDCAccountPreAuthCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation})
	owner := &samlPreparationParticipant{
		outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}},
		original:                     command,
		proof:                        *plan.Capability,
	}
	c, _, _ := coordinatorFixture(t)
	registry, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner, &capabilityExecutionProbe{}})
	if err != nil {
		t.Fatal("could not enroll the complete native SAML owner", err)
	}
	c.registry = registry
	plan.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, plan.Feature.Operation, plan.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	_, admitted, selected, err := c.prepareFeaturePreparation(command, plan)
	if err != nil || admitted == nil || selected != owner || admitted.capability == nil || *admitted.capability != owner.proof {
		t.Fatal("registered gated ACS owner could not select the original proof", err)
	}
	reservation := &reservationState{plan: admitted, journal: journalReservation{generation: 3}}
	state := &workState{ctx: t.Context(), binding: b, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, execution: &domainExecution{reservation: reservation}}
	w := Work{state: state}
	if _, err := w.SSOSAMLSigninConsumption(owner); err == nil {
		t.Fatal("Apply with no consumed capability exposed state")
	}
	state.oauthSigninStage = oauthSigninStateConsumed
	got, err := w.SSOSAMLSigninConsumption(owner)
	if err != nil || got.Command != b || got.Plan != owner.proof || got.Generation != 3 {
		t.Fatal("exact registered Apply lost its provisional SAML consumption", err)
	}
	if _, err := w.SSOOAuth2SigninConsumption(owner); err == nil {
		t.Fatal("OAuth2 borrowed an already consumed SAML capability")
	}
	state.featureApplying = false
	if _, err := w.SSOSAMLSigninConsumption(owner); err == nil {
		t.Fatal("SAML proof escaped synchronous Apply")
	}
}
