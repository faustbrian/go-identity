package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type mfaAttemptProbe struct {
	mfaCompletionValidationParticipant
}

func (*mfaAttemptProbe) RecordMFATOTPAttemptDenial(context.Context, MFATOTPAttemptWork) (MFAAttemptDisposition, error) {
	return MFAAttemptDenied, nil
}

func TestMFATOTPAttemptPreparationRequiresOriginalOpaqueCompletion(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, p := mfaCompletionPlanFixture(t, "totp-verify")
	op := p.Feature.Operation
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}}
	withBrowser := func(spec identity.FeatureCommandSpec, value string) identity.Command {
		t.Helper()
		code, err := auth.NewOneTimeCode(value)
		if err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := withBrowser(spec, "123456")
	owner := &mfaAttemptProbe{mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, expected: command, proof: *p.Capability}, completion: *p.MFACompletion}}
	registry, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	p.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.PrepareMFATOTPAttemptPlan(b, command, p)
	if err != nil || got.MFACompletion == nil || *got.MFACompletion != owner.completion || got.OTP != nil {
		t.Fatal("native counted TOTP admission unavailable", err)
	}
	if _, err := c.PrepareMFATOTPAttemptPlanWithOriginal(command, command, got); err == nil {
		t.Fatal("unmapped original admitted through protected-counter separation")
	}
	preparedSpec := spec
	preparedSpec.Fields = append(append([]identity.FeatureField(nil), spec.Fields...),
		identity.FeatureField{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}},
		identity.FeatureField{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		identity.FeatureField{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-user"}},
		identity.FeatureField{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}},
		identity.FeatureField{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}},
		identity.FeatureField{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}})
	preparedCommand := withBrowser(preparedSpec, "123456")
	owner.expected = preparedCommand
	withCounters := p
	withCounters.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{9}}
	originalPlan, err := c.PrepareMFATOTPAttemptPlanWithOriginal(command, preparedCommand, withCounters)
	if err != nil {
		t.Fatal("separated original intent unavailable", err)
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	want, err := FeaturePlanDigest(b, claimFingerprint(c.keys.retained[c.keys.current], q.canonical), originalPlan)
	if err != nil || want != originalPlan.Digest {
		t.Fatal("mapped counters replaced original journal identity", err)
	}
	changed := withBrowser(preparedSpec, "654321")
	owner.expected = changed
	if _, err := c.PrepareMFATOTPAttemptPlanWithOriginal(command, changed, withCounters); err == nil {
		t.Fatal("changed opaque code admitted as original")
	}
	extra := preparedSpec
	extra.Fields = append(append([]identity.FeatureField(nil), preparedSpec.Fields...), identity.FeatureField{Name: "counter.unrecognized", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	changed = withBrowser(extra, "123456")
	owner.expected = changed
	if _, err := c.PrepareMFATOTPAttemptPlanWithOriginal(command, changed, withCounters); err == nil {
		t.Fatal("unrecognized counter transformation admitted")
	}
	owner.expected = command
	if _, err := c.PrepareCommandPlan(b, command, got); err == nil {
		t.Fatal("counted declaration enabled ordinary opaque execution")
	}
	plain := featureCodecCommand(t, spec)
	if _, err := c.PrepareMFATOTPAttemptPlan(b, plain, got); err == nil {
		t.Fatal("code-free attempt admitted")
	}
	bad := got
	bad.MFACompletion = cloneMFACompletionPlan(got.MFACompletion)
	bad.MFACompletion.ContinuationVersion++
	if _, err := c.PrepareMFATOTPAttemptPlan(b, command, bad); err == nil {
		t.Fatal("substituted continuation admitted")
	}
	got.MFACompletion.ScopeDigest[0]++
	if p.MFACompletion.ScopeDigest != owner.completion.ScopeDigest {
		t.Fatal("returned projection aliases original scope")
	}
}

func TestMFATOTPAttemptZeroWorkDenies(t *testing.T) {
	var w MFATOTPAttemptWork
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
		t.Fatal("zero counted work admitted directory authority")
	}
	if err := w.RequireRecipient(t.Context(), nil, RecipientRecord{}); err == nil {
		t.Fatal("zero counted work admitted recipient authority")
	}
	if now, err := w.RequireRecipientCredential(t.Context(), nil, RecipientRecord{}, CredentialAdmission{}); err == nil || !now.IsZero() {
		t.Fatal("zero counted work admitted credential authority")
	}
	if _, err := w.ReserveCommandCounters(t.Context(), nil); err == nil {
		t.Fatal("zero counted work charged risk")
	}
	if _, _, err := (CommandCounterWork{}).MFACompletionScope(nil); err == nil {
		t.Fatal("zero counter work disclosed MFA scope")
	}
}
