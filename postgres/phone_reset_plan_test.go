package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// This fixture tests the kernel's closed declaration grammar, not genuine
// phone possession, signed recovery admission or an executable reset service.
func phoneResetPlanFixture(t *testing.T) (identity.Command, CommandPlan) {
	t.Helper()
	legacy, p, _ := resetPlanFixture(t)
	s, _ := legacy.PasswordResetFeature()
	s.Operation = phoneResetCodecSpec().Operation
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	_, proof, _ := legacy.PasswordResetCustody()
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	command, err := identity.NewFeaturePhonePasswordResetCommand(s, "synthetic-hash", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	p.Feature.Operation = s.Operation
	p.Audits[0].EventType = s.Operation.OperationID
	p.CommandCounters = nil
	p.OTP = &OTPAttemptPlan{AttemptID: "AwMDAwMDAwMDAwMDAwMDAw", AttemptFingerprint: [32]byte{6}, FingerprintKeyVersion: 1, ChallengeID: "synthetic-challenge", ScopeDigest: [32]byte{7}, DigestKeyVersion: 1, ExpectedVersion: 1, Mode: OTPConsume}
	now := time.Unix(1700000000, 0).UTC()
	p.RiskEvidence = &RiskEvidencePlan{
		IssuanceCommandID: "AgICAgICAgICAgICAgICAg", Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID), IssuerActor: string(s.Binding.ActorID),
		Purpose: "phone-password-reset-complete", Phase: "phone-reset-completion", RecoveryOperation: s.Operation.OperationID, PolicyVersion: 1, KeyVersion: 1,
		IntentDigest: [32]byte{8}, ConsumerCommandID: string(s.Binding.CommandID), ConsumerActor: string(s.Binding.ActorID), EvidenceDigest: [32]byte{9}, ProofDigest: [32]byte{10}, Signature: [32]byte{11},
		IssuedAt: now, CheckedAt: now.Add(time.Millisecond), ExpiresAt: now.Add(time.Minute),
	}
	p.Capability.Purpose = "identity.phone.password-reset-complete"
	// The canonical password/reset writer is unchanged; OTP and risk remain
	// distinct enlisted owners, with capability's existing terminal position.
	p.Contributors = append(p.Contributors[:4:4], otpDescriptor(), p.Contributors[4], p.Contributors[5])
	return command, p
}

func TestPhoneResetPlanRetainsAllAtomicParticipants(t *testing.T) {
	command, p := phoneResetPlanFixture(t)
	s, _ := command.PhonePasswordResetFeature()
	wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal("complete joint phone-reset declaration rejected", err)
	}
	got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire)
	if err != nil || got.Capability == nil || got.OTP == nil || got.RiskEvidence == nil || got.Digest != sha256.Sum256(wire) || *got.Capability != *p.Capability || *got.OTP != *p.OTP || *got.RiskEvidence != *p.RiskEvidence || *got.Feature != *p.Feature || len(got.Contributors) != len(p.Contributors) {
		t.Fatal("history lost original proof, joint attempt or completion risk", err)
	}
	for i := range p.Contributors {
		if got.Contributors[i] != p.Contributors[i] {
			t.Fatal("participant identity/order changed")
		}
	}
	if preparationProtected(p) || !preparationFinalDeclaration(s.Binding, p, p) {
		t.Fatal("original conjunction cannot survive hash preparation unchanged")
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated joint declaration accepted")
		}
	}
	legacy, old, _ := resetPlanFixture(t)
	oldSpec, _ := legacy.PasswordResetFeature()
	oldWire, err := encodeFeaturePlan(oldSpec.Binding, [32]byte{1}, old)
	if err != nil {
		t.Fatal("existing emailed reset became invalid", err)
	}
	if _, err := decodeFeaturePlan(s.Binding, [32]byte{1}, oldWire); err == nil {
		t.Fatal("phone recovery accepted emailed reset history")
	}
	if _, err := decodeFeaturePlan(oldSpec.Binding, [32]byte{1}, wire); err == nil {
		t.Fatal("emailed reset accepted phone recovery history")
	}
}

func TestPhoneResetPlanCannotDropOrSubstituteRequiredAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*CommandPlan){
		"missing capability":     func(p *CommandPlan) { p.Capability = nil },
		"missing OTP":            func(p *CommandPlan) { p.OTP = nil },
		"missing risk":           func(p *CommandPlan) { p.RiskEvidence = nil },
		"check-only OTP":         func(p *CommandPlan) { p.OTP.Mode = OTPCheck },
		"initiation purpose":     func(p *CommandPlan) { p.RiskEvidence.Purpose = "phone-password-reset-initiate" },
		"initiation phase":       func(p *CommandPlan) { p.RiskEvidence.Phase = "phone-reset-initiation" },
		"foreign risk operation": func(p *CommandPlan) { p.RiskEvidence.RecoveryOperation = "identity.phone.password-reset-request" },
		"same risk issuance":     func(p *CommandPlan) { p.RiskEvidence.IssuanceCommandID = p.RiskEvidence.ConsumerCommandID },
		"email capability":       func(p *CommandPlan) { p.Capability.Purpose = "identity.password.reset-complete" },
		"reusable capability":    func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		"counters instead of proof": func(p *CommandPlan) {
			p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{1}}
		},
		"new issuance":             func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"new delivery":             func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"foreign owner":            func(p *CommandPlan) { p.Feature.Contributor.Owner = "identity/phone/postgres" },
		"schema alias":             func(p *CommandPlan) { p.Feature.Operation.SchemaID = "alias" },
		"future schema":            func(p *CommandPlan) { p.Feature.Operation.SchemaVersion++ },
		"wrong subject":            func(p *CommandPlan) { p.SubjectType = "phone" },
		"unprotected audit":        func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"wrong lifecycle":          func(p *CommandPlan) { p.Lifecycle.EventType = "password.changed.v1" },
		"missing capability owner": func(p *CommandPlan) { p.Contributors = p.Contributors[:len(p.Contributors)-1] },
		"missing OTP owner":        func(p *CommandPlan) { p.Contributors[4] = p.Contributors[5] },
	} {
		t.Run(name, func(t *testing.T) {
			command, p := phoneResetPlanFixture(t)
			s, _ := command.PhonePasswordResetFeature()
			mutate(&p)
			if _, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p); err == nil {
				t.Fatal("incomplete/foreign phone reset admitted")
			}
		})
	}
}

func TestPhoneResetPreparationCannotChangeOriginalConjunction(t *testing.T) {
	for name, mutate := range map[string]func(*CommandPlan){
		"OTP attempt":      func(p *CommandPlan) { p.OTP.AttemptID = "BAQEBAQEBAQEBAQEBAQEBA" },
		"OTP input":        func(p *CommandPlan) { p.OTP.AttemptFingerprint[0]++ },
		"OTP scope":        func(p *CommandPlan) { p.OTP.ScopeDigest[0]++ },
		"risk proof":       func(p *CommandPlan) { p.RiskEvidence.ProofDigest[0]++ },
		"risk deadline":    func(p *CommandPlan) { p.RiskEvidence.ExpiresAt = p.RiskEvidence.ExpiresAt.Add(time.Second) },
		"reset capability": func(p *CommandPlan) { p.Capability.ProofFingerprint[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			command, original := phoneResetPlanFixture(t)
			s, _ := command.PhonePasswordResetFeature()
			_, final := phoneResetPlanFixture(t)
			mutate(&final)
			if preparationFinalDeclaration(s.Binding, original, final) {
				t.Fatal("hash generation replaced/renewed original authority")
			}
			first, err := encodeFeaturePlan(s.Binding, [32]byte{1}, original)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := encodeFeaturePlan(s.Binding, [32]byte{1}, final)
			if err != nil || bytes.Equal(first, changed) {
				t.Fatal("retained plan omitted changed original intent", err)
			}
		})
	}
}

func TestPhoneResetIntentUsesExistingResetMutationOwner(t *testing.T) {
	command, p := phoneResetPlanFixture(t)
	s, _ := command.PhonePasswordResetFeature()
	_, _, i := resetPlanFixture(t)
	native := resetMappingPhase{intent: i}
	if got, err := credentialResetCommand(native, command, p); err != nil || got != i {
		t.Fatal("joint recovery cannot select canonical password replacement", err)
	}
	for name, mutate := range map[string]func(*CommandPlan, *resetMappingPhase){
		"missing OTP":       func(p *CommandPlan, _ *resetMappingPhase) { p.OTP = nil },
		"missing risk":      func(p *CommandPlan, _ *resetMappingPhase) { p.RiskEvidence = nil },
		"missing proof":     func(p *CommandPlan, _ *resetMappingPhase) { p.Capability = nil },
		"foreign authority": func(_ *CommandPlan, n *resetMappingPhase) { n.intent.Replacement.ExpectedAuthorityVersion++ },
		"wrong successor":   func(p *CommandPlan, _ *resetMappingPhase) { p.Lifecycle.AfterVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			_, changed := phoneResetPlanFixture(t)
			n := native
			mutate(&changed, &n)
			if _, err := credentialResetCommand(n, command, changed); err == nil {
				t.Fatal("incomplete joint reset reached mutation owner")
			}
		})
	}
	if _, err := credentialResetCommand(native, featureCodecCommand(t, s), p); err == nil {
		t.Fatal("generic metadata reached mutation owner without joint custody")
	}
	if _, err := decodeCredentialCompromise(s); err == nil {
		t.Fatal("phone recovery widened ordinary compromise ownership")
	}
	if _, err := decodeCredentialReplacement(s); err == nil {
		t.Fatal("phone recovery widened ordinary password-change ownership")
	}
}

func TestPhoneResetRegistryReservesExactExistingPasswordOwner(t *testing.T) {
	_, p := phoneResetPlanFixture(t)
	for _, accepted := range []bool{true, false} {
		for _, mutate := range []func(*featureRegistryContributor){
			func(c *featureRegistryContributor) { c.descriptor.Owner = "identity/phone/postgres" },
			func(c *featureRegistryContributor) { c.descriptor.ContractID = "identity.phone" },
			func(c *featureRegistryContributor) { c.operations[0].SchemaID = "alias" },
			func(c *featureRegistryContributor) { c.operations[0].SchemaVersion++ },
			func(c *featureRegistryContributor) { c.operations[0].Owner = "identity/password" },
		} {
			c := &featureRegistryContributor{descriptor: p.Feature.Contributor, operations: []identity.FeatureOperation{p.Feature.Operation}}
			if !accepted {
				mutate(c)
			}
			r, err := NewContributorRegistry([]Contributor{c})
			if accepted && (err != nil || len(r.FeatureOperations()) != 1) {
				t.Fatal("canonical reset owner cannot register exact phone operation", err)
			}
			if !accepted && err == nil {
				t.Fatal("foreign owner/schema acquired phone recovery")
			}
		}
	}
}

// These owners are deliberately non-executing unit seams. They exercise real
// public preparation/registry checks, never create a Work or prove possession.
type phoneResetPreparationProbe struct{ scopeFeatureParticipant }

func (*phoneResetPreparationProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*phoneResetPreparationProbe) CredentialReset(c identity.Command) (CredentialResetIntent, error) {
	f, ok := c.PhonePasswordResetFeature()
	if !ok {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	return decodeCredentialReset(f)
}
func (*phoneResetPreparationProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (*phoneResetPreparationProbe) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (*phoneResetPreparationProbe) ValidateFeaturePreparation(identity.Command, CommandPlan) error {
	return nil
}
func (*phoneResetPreparationProbe) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*phoneResetPreparationProbe) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error) {
	return identity.Command{}, CommandPlan{}, invalidPreparation()
}
func (*phoneResetPreparationProbe) PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}
func (*phoneResetPreparationProbe) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

type phoneResetOutboxProbe struct{ riskPassiveProbe }

func (*phoneResetOutboxProbe) PersistCredentialReset(context.Context, Work) error {
	return invalidWork()
}

func TestPhoneResetOTPPreparationSelectsClosedCompoundCustody(t *testing.T) {
	command, p := phoneResetPlanFixture(t)
	s, _ := command.PhonePasswordResetFeature()
	c, _, _ := coordinatorFixture(t)
	owner := &phoneResetPreparationProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}}
	registry, err := NewContributorRegistry([]Contributor{
		&Repository{},
		&riskPassiveProbe{registryContributor{p.Contributors[1]}},
		&phoneResetOutboxProbe{riskPassiveProbe{registryContributor{p.Contributors[2]}}},
		owner, &otpExecutionProbe{}, &riskReservationProbe{}, &capabilityExecutionProbe{},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.registry, p.Contributors = registry, registry.Descriptors()
	kind := audit.ActorService
	if s.Binding.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, kind, "identity-feature-audit-binding-v1")
	prepared, err := c.PrepareOTPReservationPlan(s.Binding, command, p)
	if err != nil || prepared.Digest == ([32]byte{}) || prepared.Capability == nil || prepared.RiskEvidence == nil || prepared.OTP == nil {
		t.Fatal("complete native joint command cannot select existing OTP owner", err)
	}
	if _, err := c.PrepareCommandPlan(s.Binding, command, prepared); err == nil {
		t.Fatal("generic execution bypassed the dedicated consuming path")
	}
	if _, _, _, err := c.prepareRestoredFeature(s.Binding, command, prepared); err != nil {
		t.Fatal("retained generated output cannot restore original joint participants", err)
	}
	if !otpFeatureInputAdmissionRequired(prepared) {
		t.Fatal("joint denial/reservation omitted original native admission")
	}
}

func FuzzPhoneResetPlan(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa5})
	f.Add([]byte{0xa5, 0x64, 'b', 'a', 's', 'e', 0x41, 0xaa})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65537 {
			return
		}
		command, plan := phoneResetPlanFixture(t)
		spec, _ := command.PhonePasswordResetFeature()
		if len(data) == 0 {
			var err error
			data, err = encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, data)
		if err != nil {
			return
		}
		canonical, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, got)
		if err != nil || !bytes.Equal(canonical, data) || got.Digest != sha256.Sum256(data) {
			t.Fatal("phone reset history accepted a noncanonical declaration")
		}
	})
}
