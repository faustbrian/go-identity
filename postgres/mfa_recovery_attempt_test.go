package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type recoveryAttemptProbe struct {
	mfaCompletionValidationParticipant
}

func (*recoveryAttemptProbe) RecordMFARecoveryAttemptDenial(context.Context, MFARecoveryAttemptWork) (MFAAttemptDisposition, error) {
	return MFAAttemptDenied, nil
}

func TestRecoveryAttemptUsesDistinctNativeAdmission(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, p := mfaCompletionPlanFixture(t, "recovery-use")
	op := p.Feature.Operation
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}}
	code, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	command, err := identity.NewFeatureRecoveryCodePreAuthCommand(spec, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	owner := &recoveryAttemptProbe{mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, expected: command, proof: *p.Capability}, completion: *p.MFACompletion}}
	registry, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}})
	if err != nil {
		t.Fatal(err)
	}
	c.registry, p.Contributors = registry, registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := c.PrepareMFARecoveryAttemptPlan(b, command, p)
	if err != nil || prepared.MFACompletion == nil || *prepared.MFACompletion != owner.completion || prepared.OTP != nil {
		t.Fatal("native recovery admission unavailable", err)
	}
	if _, err := c.PrepareMFATOTPAttemptPlan(b, command, p); err == nil {
		t.Fatal("recovery admitted through TOTP route")
	}
	if _, err := c.PrepareCommandPlan(b, command, prepared); err == nil {
		t.Fatal("recovery admitted through ordinary route")
	}
	preparedSpec := spec
	preparedSpec.Fields = append(append([]identity.FeatureField(nil), spec.Fields...),
		identity.FeatureField{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}},
		identity.FeatureField{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		identity.FeatureField{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-user"}},
		identity.FeatureField{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}},
		identity.FeatureField{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}},
		identity.FeatureField{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}})
	mapped, err := identity.NewFeatureRecoveryCodePreAuthCommand(preparedSpec, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	owner.expected = mapped
	withCounters := p
	withCounters.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{9}}
	originalPlan, err := c.PrepareMFARecoveryAttemptPlanWithOriginal(command, mapped, withCounters)
	if err != nil {
		t.Fatal("recovery original intent separation unavailable", err)
	}
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	want, err := FeaturePlanDigest(b, claimFingerprint(c.keys.retained[c.keys.current], claim.canonical), originalPlan)
	if err != nil || want != originalPlan.Digest {
		t.Fatal("recovery counter preparation replaced submitted identity", err)
	}
	otherCode, _ := auth.NewRecoveryCode("different-recovery-code")
	changed, _ := identity.NewFeatureRecoveryCodePreAuthCommand(preparedSpec, otherCode, auth.NewBearerCredential(strings.Repeat("A", 43)))
	owner.expected = changed
	if _, err := c.PrepareMFARecoveryAttemptPlanWithOriginal(command, changed, withCounters); err == nil {
		t.Fatal("changed recovery code admitted as original")
	}
	changed, _ = identity.NewFeatureRecoveryCodePreAuthCommand(preparedSpec, code, auth.NewBearerCredential(strings.Repeat("B", 43)))
	owner.expected = changed
	if _, err := c.PrepareMFARecoveryAttemptPlanWithOriginal(command, changed, withCounters); err == nil {
		t.Fatal("changed recovery browser admitted as original")
	}
	owner.expected = mapped
	if _, err := c.PrepareMFATOTPAttemptPlanWithOriginal(command, mapped, withCounters); err == nil {
		t.Fatal("original recovery pair admitted through TOTP")
	}
	otp, _ := auth.NewOneTimeCode("123456")
	foreign, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, otp, auth.NewBearerCredential(strings.Repeat("A", 43)))
	owner.expected = foreign
	if _, err := c.PrepareMFARecoveryAttemptPlan(b, foreign, p); err == nil {
		t.Fatal("recovery operation accepted OTP custody")
	}
}

func TestRecoveryAttemptZeroWorkDenies(t *testing.T) {
	var w MFARecoveryAttemptWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero work disclosed binding")
	}
	if _, err := w.NativeCommand(nil); err == nil {
		t.Fatal("zero work disclosed code")
	}
	if _, err := w.Exec(t.Context(), "SELECT 1"); err == nil {
		t.Fatal("zero work mutated")
	}
	if _, err := w.Query(t.Context(), "SELECT 1"); err == nil {
		t.Fatal("zero work read")
	}
	if _, err := w.DatabaseTime(t.Context()); err == nil {
		t.Fatal("zero work read clock")
	}
	if err := w.RequireActiveDirectoryAuthority(t.Context(), nil, DirectoryAuthorityAdmission{}); err == nil {
		t.Fatal("zero recovery work admitted directory authority")
	}
	if err := w.RequireRecipient(t.Context(), nil, RecipientRecord{}); err == nil {
		t.Fatal("zero recovery work admitted recipient")
	}
	if now, err := w.RequireRecipientCredential(t.Context(), nil, RecipientRecord{}, CredentialAdmission{}); err == nil || !now.IsZero() {
		t.Fatal("zero recovery work admitted password authority")
	}
	if _, err := w.ReserveCommandCounters(t.Context(), nil); err == nil {
		t.Fatal("zero recovery work charged risk")
	}
}
