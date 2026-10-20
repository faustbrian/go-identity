package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/faustbrian/go-audit"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Independent native participant fixtures exercise coordinator admission and
// lifetime, not cryptographic authenticity or the production risk journal.
type riskReservationProbe struct{ retained RiskReservationWork }

func (*riskReservationProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (p *riskReservationProbe) ReserveRiskEvidence(ctx context.Context, w RiskReservationWork) error {
	p.retained = w
	_, err := w.Binding(p)
	return err
}
func (p *riskReservationProbe) RebindRiskEvidence(ctx context.Context, w RiskReservationWork) error {
	p.retained = w
	_, err := w.Binding(p)
	return err
}
func (*riskReservationProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

type phoneReservationProbe struct{}

type riskPassiveProbe struct{ registryContributor }

func (*riskPassiveProbe) PersistAudits(context.Context, Work) error    { return nil }
func (*riskPassiveProbe) PersistLifecycle(context.Context, Work) error { return nil }
func (*riskPassiveProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func (*phoneReservationProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}
}
func (*phoneReservationProbe) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*phoneReservationProbe) ValidateFeatureCommand(c identity.Command, p CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != (&phoneReservationProbe{}).FeatureOperations()[0] || p.RiskEvidence == nil || p.SubjectType != "phone" {
		return invalidPlan()
	}
	return nil
}
func (*phoneReservationProbe) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, invalidWork()
}
func (*phoneReservationProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func riskReservationFixture(t *testing.T, participant Contributor) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, p := featurePlanFixture(t)
	f := &phoneReservationProbe{}
	r, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{p.Contributors[0]}}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, f, participant})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	s := featureCodecSpec()
	s.Operation = f.FeatureOperations()[0]
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	p.Feature = &FeatureRegistration{Contributor: f.Descriptor(), Operation: s.Operation}
	p.SubjectType = "phone"
	p.Contributors = r.Descriptors()
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "phone.reset", "protected"
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, "phone", s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	p.Lifecycle.EventType = "phone.reset.v1"
	now := time.Now().UTC().Truncate(time.Microsecond)
	p.RiskEvidence = &RiskEvidencePlan{IssuanceCommandID: "AgICAgICAgICAgICAgICAg", Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID), IssuerActor: string(s.Binding.ActorID), Purpose: "phone-password-reset-initiate", Phase: "phone-reset-initiation", RecoveryOperation: s.Operation.OperationID, PolicyVersion: 1, KeyVersion: 1, IntentDigest: [32]byte{2}, ConsumerCommandID: string(s.Binding.CommandID), ConsumerActor: string(s.Binding.ActorID), EvidenceDigest: [32]byte{3}, ProofDigest: [32]byte{4}, Signature: [32]byte{5}, IssuedAt: now, CheckedAt: now.Add(time.Nanosecond), ExpiresAt: now.Add(time.Minute)}
	return c, featureCodecCommand(t, s), p
}

func TestRiskReservationPlanOwnsSignedDeclaration(t *testing.T) {
	c, command, p := riskReservationFixture(t, &riskReservationProbe{})
	s, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal("typed risk initiation rejected", err)
	}
	want := *prepared.RiskEvidence
	p.RiskEvidence.IntentDigest[0]++
	if *prepared.RiskEvidence != want {
		t.Fatal("caller altered prepared risk scope")
	}
	q, _, admitted, err := c.prepare(s.Binding, command, prepared)
	if err != nil || admitted.risk == nil || *admitted.risk != want || admitted.fingerprint != claimFingerprint(c.keys.retained[1], q.canonical) {
		t.Fatal("risk admission lost scope", err)
	}
	snapshot := admitted.snapshot()
	snapshot.RiskEvidence.EvidenceDigest[0]++
	if *admitted.risk != want {
		t.Fatal("admission aliased snapshot")
	}
	r := Reservation{state: &reservationState{coordinator: c, plan: admitted}}
	if _, err := c.Begin(context.Background(), r); err == nil || r.state.started.Load() {
		t.Fatal("reservation enabled unfinished domain phases")
	}
	wire, err := encodeFeaturePlan(s.Binding, admitted.fingerprint, prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(s.Binding, admitted.fingerprint, wire)
	if err != nil || decoded.RiskEvidence == nil || *decoded.RiskEvidence != want || decoded.Digest != prepared.Digest {
		t.Fatal("frozen risk declaration lost", err)
	}
	if _, err := KernelPlanDigest(s.Binding, admitted.fingerprint, prepared); err == nil {
		t.Fatal("kernel silently omitted risk")
	}
	for _, bad := range [][]byte{append(append([]byte(nil), wire...), 0), bytes.Replace(wire, []byte("identity-feature-risk-plan-v1"), []byte("identity-feature-risk-plan-v2"), 1)} {
		if _, err := decodeFeaturePlan(s.Binding, admitted.fingerprint, bad); err == nil {
			t.Fatal("noncanonical risk plan decoded")
		}
	}
}

func TestRiskPlanBindsEveryNativeField(t *testing.T) {
	c, command, p := riskReservationFixture(t, &riskReservationProbe{})
	s, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := prepareClaim(command, c.keys.retained[1])
	fp := claimFingerprint(c.keys.retained[1], q.canonical)
	for _, change := range []func(*RiskEvidencePlan){
		func(p *RiskEvidencePlan) { p.IssuanceCommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(p *RiskEvidencePlan) { p.IssuerActor += "x" }, func(p *RiskEvidencePlan) { p.PolicyVersion++ }, func(p *RiskEvidencePlan) { p.KeyVersion++ },
		func(p *RiskEvidencePlan) { p.IntentDigest[0]++ }, func(p *RiskEvidencePlan) { p.EvidenceDigest[0]++ }, func(p *RiskEvidencePlan) { p.ProofDigest[0]++ }, func(p *RiskEvidencePlan) { p.Signature[0]++ },
		func(p *RiskEvidencePlan) { p.IssuedAt = p.IssuedAt.Add(-time.Microsecond) }, func(p *RiskEvidencePlan) { p.CheckedAt = p.CheckedAt.Add(time.Nanosecond) }, func(p *RiskEvidencePlan) { p.ExpiresAt = p.ExpiresAt.Add(-time.Microsecond) },
	} {
		candidate := prepared
		cp := *prepared.RiskEvidence
		candidate.RiskEvidence = &cp
		change(&cp)
		digest, err := FeaturePlanDigest(s.Binding, fp, candidate)
		if err != nil || digest == prepared.Digest {
			t.Fatal("signed declaration omitted", err)
		}
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.RiskEvidence = nil }, func(p *CommandPlan) { p.RiskEvidence.Tenant += "x" }, func(p *CommandPlan) { p.RiskEvidence.Subject += "x" }, func(p *CommandPlan) { p.RiskEvidence.ConsumerActor += "x" }, func(p *CommandPlan) { p.RiskEvidence.ConsumerCommandID = p.RiskEvidence.IssuanceCommandID },
		func(p *CommandPlan) { p.RiskEvidence.Purpose = "phone-password-reset-complete" }, func(p *CommandPlan) { p.RiskEvidence.Phase = "phone-reset-completion" }, func(p *CommandPlan) { p.RiskEvidence.RecoveryOperation = "identity.phone.password-reset-complete" },
		func(p *CommandPlan) { p.RiskEvidence.Signature = [32]byte{} }, func(p *CommandPlan) { p.RiskEvidence.ExpiresAt = p.RiskEvidence.IssuedAt }, func(p *CommandPlan) { p.RiskEvidence.CheckedAt = p.RiskEvidence.ExpiresAt }, func(p *CommandPlan) { p.RiskEvidence.IssuedAt = p.RiskEvidence.IssuedAt.Add(time.Nanosecond) },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} }, func(p *CommandPlan) { p.SubjectType = "" }, func(p *CommandPlan) { p.Feature.Operation.SchemaID += ".other" }, func(p *CommandPlan) { p.Contributors[4].Version++ },
	} {
		candidate := prepared
		cp := *prepared.RiskEvidence
		f := *prepared.Feature
		candidate.RiskEvidence = &cp
		candidate.Feature = &f
		candidate.Contributors = append([]ContributorDescriptor(nil), prepared.Contributors...)
		change(&candidate)
		if _, err := FeaturePlanDigest(s.Binding, fp, candidate); err == nil {
			t.Fatal("invalid risk declaration accepted")
		}
	}
}

func TestRiskReservationZeroAndRedaction(t *testing.T) {
	var w RiskReservationWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero binding")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero exec")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); err == nil || rows != nil {
		t.Fatal("zero query")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero time")
	}
	for _, v := range []any{w, RiskReservationBinding{}, RiskEvidencePlan{}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("serialized risk authority")
		}
		if !bytes.Contains([]byte(fmt.Sprintf("%#v", v)), []byte("(redacted)")) {
			t.Fatal("unredacted risk authority")
		}
	}
}

func TestRiskPreparationRequiresNativeParticipantAndCompleteProfile(t *testing.T) {
	for _, participant := range []Contributor{&registryContributor{ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}}, &riskPassiveProbe{registryContributor{ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}}}} {
		c, command, p := riskReservationFixture(t, participant)
		s, _ := command.Feature()
		if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
			t.Fatal("name-only risk contributor admitted")
		}
	}
	_, command, p := riskReservationFixture(t, &riskReservationProbe{})
	s, _ := command.Feature()
	p.RiskEvidence = nil
	p.Contributors = p.Contributors[:4]
	if _, err := FeaturePlanDigest(s.Binding, [32]byte{1}, p); err == nil {
		t.Fatal("reset initiation bypassed risk declaration")
	}
	s.Operation.OperationID = "identity.phone.password-reset-complete"
	s.Binding.OperationID = s.Operation.OperationID
	p.Feature.Operation = s.Operation
	if _, err := FeaturePlanDigest(s.Binding, [32]byte{1}, p); err == nil {
		t.Fatal("completion enabled without OTP/capability")
	}
}

type riskIssuanceAdmissionProbe struct{ phoneReservationProbe }

func (*riskIssuanceAdmissionProbe) Descriptor() ContributorDescriptor {
	return (&riskReservationProbe{}).Descriptor()
}
func (*riskIssuanceAdmissionProbe) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/risk", OperationID: "identity.risk.evaluate", SchemaID: "identity-risk-evidence-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*riskIssuanceAdmissionProbe) ValidateFeatureCommand(c identity.Command, p CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != (&riskIssuanceAdmissionProbe{}).FeatureOperations()[0] || p.RiskEvidence != nil || p.SubjectType != "risk_evidence" {
		return invalidPlan()
	}
	return nil
}

func TestRiskIssuanceAdmissionDoesNotRequireConsumptionRole(t *testing.T) {
	c, _, p := featurePlanFixture(t)
	participant := &riskIssuanceAdmissionProbe{}
	r, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{p.Contributors[0]}}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, participant})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	s := featureCodecSpec()
	s.Operation = participant.FeatureOperations()[0]
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	p.Feature = &FeatureRegistration{Contributor: participant.Descriptor(), Operation: s.Operation}
	p.SubjectType = "risk_evidence"
	p.Contributors = r.Descriptors()
	p.Audits[0].RetentionClass = "protected"
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	prepared, err := c.PrepareCommandPlan(s.Binding, featureCodecCommand(t, s), p)
	if err != nil || prepared.RiskEvidence != nil || len(prepared.Contributors) != 4 {
		t.Fatal("existing issuance required consumption", err)
	}
}

func TestKernelPreparationRejectsRatherThanDropsRiskDeclaration(t *testing.T) {
	c, command, p := coordinatorFixture(t)
	s, _ := command.CreateUser()
	p.RiskEvidence = &RiskEvidencePlan{}
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
		t.Fatal("kernel preparation silently discarded risk")
	}
	if _, _, _, err := c.prepare(s.Binding, command, p); err == nil {
		t.Fatal("kernel reservation admission discarded risk")
	}
	if r, _, err := c.ReserveCommand(context.Background(), s.Binding, command, p); err == nil || r.state != nil {
		t.Fatal("unsupported risk reservation granted")
	}
}

func FuzzRiskFrozenPlan(f *testing.F) {
	s := featureCodecSpec()
	s.Operation = (&phoneReservationProbe{}).FeatureOperations()[0]
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	p := CommandPlan{SubjectType: "phone", Feature: &FeatureRegistration{Operation: s.Operation, Contributor: (&phoneReservationProbe{}).Descriptor()}, Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, (&phoneReservationProbe{}).Descriptor(), (&riskReservationProbe{}).Descriptor()}, Audits: []AuditPlan{{EventType: "phone.reset", SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionPolicyVersion: 1, RetentionClass: "protected", RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: "phone.reset.v1", AfterVersion: 1}, RiskEvidence: &RiskEvidencePlan{IssuanceCommandID: "AgICAgICAgICAgICAgICAg", Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID), IssuerActor: string(s.Binding.ActorID), Purpose: "phone-password-reset-initiate", Phase: "phone-reset-initiation", RecoveryOperation: s.Operation.OperationID, PolicyVersion: 1, KeyVersion: 1, IntentDigest: [32]byte{1}, ConsumerCommandID: string(s.Binding.CommandID), ConsumerActor: string(s.Binding.ActorID), EvidenceDigest: [32]byte{2}, ProofDigest: [32]byte{3}, Signature: [32]byte{4}, IssuedAt: now, CheckedAt: now.Add(time.Nanosecond), ExpiresAt: now.Add(time.Minute)}}
	seed, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	// Exercise the actual SMS request grammar as well as the retained legacy
	// phone-domain declaration; random mutation rarely discovers the tuple.
	p.SubjectType = "otp_challenge"
	p.Lifecycle = &LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}
	p.Audits[0].EventType = "otp.send"
	request, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(request)
	f.Add([]byte{0xa9})
	f.Add(bytes.Repeat([]byte{0}, 65537))
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, input)
		if err != nil {
			return
		}
		encoded, err := encodeFeaturePlan(s.Binding, [32]byte{1}, got)
		if err != nil || !bytes.Equal(encoded, input) || got.RiskEvidence == nil {
			t.Fatal("noncanonical risk history decoded")
		}
	})
}
