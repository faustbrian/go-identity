package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// Nonzero size makes distinct test principals have distinct pointer identity;
// Go may coalesce addresses of zero-sized values.
type captchaReservationProbe struct {
	riskIssuanceAdmissionProbe
	identity byte
}

func (*captchaReservationProbe) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/risk", OperationID: "identity.risk.captcha-issue", SchemaID: "identity-captcha-evidence-user-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, {Owner: "identity/risk", OperationID: "identity.risk.captcha-issue", SchemaID: "identity-captcha-evidence-flow-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
}
func (*captchaReservationProbe) ValidateFeatureCommand(c identity.Command, p CommandPlan) error {
	s, ok := c.Feature()
	if !ok || !captchaReplayOperation(s.Operation) || !p.CaptchaReplayReservation {
		return invalidPlan()
	}
	return nil
}

func TestCaptchaAnonymousReservationConservesSeparateNamespace(t *testing.T) {
	c, command, p := captchaReservationFixture(t)
	s, _ := command.Feature()
	s.Operation = (&captchaReservationProbe{}).FeatureOperations()[1]
	s.Binding.SchemaID = s.Operation.SchemaID
	s.Binding.UserID, s.Binding.AnonymousFlowID = "", "anonymous-flow"
	p.Feature.Operation = s.Operation
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	command = featureCodecCommand(t, s)
	p, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	q, _, admitted, err := c.prepare(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeFeaturePlan(s.Binding, admitted.fingerprint, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(s.Binding, claimFingerprint(c.keys.retained[1], q.canonical), wire)
	if err != nil || decoded.Feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || !decoded.CaptchaReplayReservation {
		t.Fatal("anonymous declaration lost", err)
	}
	foreign := s.Binding
	foreign.UserID, foreign.AnonymousFlowID = "anonymous-flow", ""
	if _, err := decodeFeaturePlan(foreign, admitted.fingerprint, wire); err == nil {
		t.Fatal("flow scope substituted by user")
	}
}
func (*captchaReservationProbe) ReserveCaptchaReplay(context.Context, CaptchaReservationWork) error {
	return nil
}
func (*captchaReservationProbe) RebindCaptchaReplay(context.Context, CaptchaReservationWork) error {
	return nil
}

func captchaReservationFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, p := featurePlanFixture(t)
	f := &captchaReservationProbe{}
	r, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{p.Contributors[0]}}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, f})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	s := featureCodecSpec()
	s.Operation = f.FeatureOperations()[0]
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.RecordID = string(s.Binding.CommandID)
	p.Feature = &FeatureRegistration{Contributor: f.Descriptor(), Operation: s.Operation}
	p.SubjectType, p.CaptchaReplayReservation = "captcha_evidence", true
	p.Contributors = r.Descriptors()
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.captcha.verify", "protected"
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	p.Lifecycle.EventType = "identity.captcha.issued.v1"
	return c, featureCodecCommand(t, s), p
}

func TestCaptchaReservationDeclarationConservedAndMandatory(t *testing.T) {
	c, command, p := captchaReservationFixture(t)
	s, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil || !prepared.CaptchaReplayReservation {
		t.Fatal("native CAPTCHA reservation missing", err)
	}
	q, _, admitted, err := c.prepare(s.Binding, command, prepared)
	if err != nil || !admitted.captchaReplay || !admitted.snapshot().CaptchaReplayReservation {
		t.Fatal("admission lost declared phase", err)
	}
	encoded, err := encodeFeaturePlan(s.Binding, claimFingerprint(c.keys.retained[1], q.canonical), prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(s.Binding, admitted.fingerprint, encoded)
	if err != nil || !decoded.CaptchaReplayReservation || decoded.Digest != prepared.Digest {
		t.Fatal("historical phase lost", err)
	}
	bad := prepared
	bad.CaptchaReplayReservation = false
	if _, err := FeaturePlanDigest(s.Binding, admitted.fingerprint, bad); err == nil {
		t.Fatal("issuance bypassed replay reservation")
	}
	if _, err := KernelPlanDigest(s.Binding, admitted.fingerprint, prepared); err == nil {
		t.Fatal("kernel omitted CAPTCHA phase")
	}
	for _, wire := range [][]byte{append(bytes.Clone(encoded), 0), bytes.Replace(encoded, []byte("identity-feature-captcha-replay-v1"), []byte("identity-feature-captcha-replay-v2"), 1)} {
		if _, err := decodeFeaturePlan(s.Binding, admitted.fingerprint, wire); err == nil {
			t.Fatal("foreign phase decoded")
		}
	}
	_, legacyCommand, legacy := featurePlanFixture(t)
	ls, _ := legacyCommand.Feature()
	legacy.CaptchaReplayReservation = true
	if _, err := FeaturePlanDigest(ls.Binding, [32]byte{1}, legacy); err == nil {
		t.Fatal("unrelated feature acquired CAPTCHA reservation")
	}
}

func TestCaptchaReservationZeroWorkDeniesAndRedacts(t *testing.T) {
	w := CaptchaReservationWork{}
	if _, err := w.Binding(&captchaReservationProbe{}); err == nil {
		t.Fatal("zero binding")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero exec")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); err == nil || rows != nil {
		t.Fatal("zero rows")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero time")
	}
	for _, v := range []any{w, CaptchaReservationBinding{}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("serialized authority")
		}
	}
}

func TestCaptchaReservationScopeLifetimeAndGeneration(t *testing.T) {
	c, command, plan := captchaReservationFixture(t)
	spec, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	_, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil {
		t.Fatal(err)
	}
	p := c.registry.state.entries[3].contributor.(CaptchaReplayContributor)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 2, registry: c.registry.state}}
	s := &captchaReservationState{coordinator: c, work: w, plan: admitted, command: command, previousGeneration: 1, active: true, contributor: p}
	handle := CaptchaReservationWork{state: s}
	b, err := handle.Binding(p)
	if err != nil || b.Fingerprint != admitted.fingerprint || b.Generation != 2 || b.PreviousGeneration != 1 {
		t.Fatal("original ownership lost", err)
	}
	got, _ := b.Command.Feature()
	if got.Binding != spec.Binding {
		t.Fatal("original command lost")
	}
	if _, err := handle.Binding(&captchaReservationProbe{}); err == nil {
		t.Fatal("foreign participant")
	}
	for _, change := range []func(*captchaReservationState){
		func(s *captchaReservationState) { s.active = false },
		func(s *captchaReservationState) { s.previousGeneration = 2 },
		func(s *captchaReservationState) { s.previousGeneration = ^uint64(0) },
		func(s *captchaReservationState) { s.coordinator = &Coordinator{} },
	} {
		copy := *s
		change(&copy)
		if _, err := (CaptchaReservationWork{state: &copy}).Binding(p); err == nil {
			t.Fatal("foreign or expired custody")
		}
	}
	s.active = false
	if _, err := handle.Binding(p); err == nil {
		t.Fatal("copy revived callback")
	}
}
