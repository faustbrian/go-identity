package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPreAuthIssueExecutorRejectsZeroComposition(t *testing.T) {
	if e, err := NewPreAuthIssueExecutor(nil, PreAuthIssueExecutorConfig{}); e != nil || err == nil {
		t.Fatal("zero composition admitted")
	}
	var e *PreAuthIssueExecutor
	if r, err := e.ExecutePreAuthIssue(context.Background(), PreAuthIssueCommand{}); err == nil || r.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero executor gained outcome")
	}
	if r, err := e.ExecutePreAuthIssuance(context.Background(), PreAuthIssueCommand{}); err == nil || r.Receipt.Outcome != identity.CommitOutcomeInvalid || !r.Replayed {
		t.Fatal("zero executor gained original delivery eligibility")
	}
	if r, err := e.RecoverPreAuthIssue(context.Background(), identity.RecoveryQuery{}); err == nil || r.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero recovery gained outcome")
	}
}

func TestPreAuthIssueNativePlanRequiresConfiguredProfile(t *testing.T) {
	record := testPreAuth(t, time.Now().UTC())
	b := preAuthIssueBinding(record)
	c, err := mapPreAuthIssue(b, record)
	if err != nil {
		t.Fatal(err)
	}
	r := &Repository{preAuthIssue: &preAuthIssueProfile{actor: b.ActorID, action: "identity.otp.signin", origin: "https://identity.test", callback: "https://app.test/return", policy: b.PolicyID, version: b.PolicyVersion}}
	p := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: r.Descriptor(), Operation: preAuthIssueOperation()}, SubjectType: "preauth_transaction", Lifecycle: &kernel.LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.preauth-issue", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err = r.ValidateFeatureCommand(c, p); err != nil {
		t.Fatal("complete native declaration denied", err)
	}
	for _, alter := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.Feature = nil },
		func(p *kernel.CommandPlan) { p.SubjectType = "user" },
		func(p *kernel.CommandPlan) {
			p.Lifecycle = &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}
		},
		func(p *kernel.CommandPlan) { p.Audits = nil },
		func(p *kernel.CommandPlan) { p.Capability = &kernel.CapabilityPlan{} },
		func(p *kernel.CommandPlan) { p.OTP = &kernel.OTPAttemptPlan{} },
	} {
		changed := p
		alter(&changed)
		if err = r.ValidateFeatureCommand(c, changed); err == nil {
			t.Fatal("incomplete or wrong-owner declaration admitted")
		}
	}
	r.preAuthIssue = nil
	if err = r.ValidateFeatureCommand(c, p); err == nil {
		t.Fatal("unconfigured native profile admitted")
	}
	var zero kernel.Work
	if _, err = r.ApplyFeature(context.Background(), zero, c); err == nil {
		t.Fatal("zero work gained mutation")
	}
	var absent session.PreAuthTransaction
	if _, err = mapPreAuthIssue(b, absent); err == nil {
		t.Fatal("zero record admitted")
	}
}
