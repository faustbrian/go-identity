package postgres

import (
	"context"
	"testing"
	"time"

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
	command := codeCodecCommand(t, spec, "123456")
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
}
