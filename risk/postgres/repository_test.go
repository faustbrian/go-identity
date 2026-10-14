package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestRepositoryRequiresOwnedConfigurationAndActiveInvocation(t *testing.T) {
	if _, err := NewRepository(Config{}); err == nil {
		t.Fatal("zero configuration admitted")
	}
	issue, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	cfg := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1"}
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := MapIssue(issue, issueBinding(issue.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplyFeature(context.Background(), identitypostgres.Work{}, cmd); err == nil {
		t.Fatal("zero Work admitted")
	}
	if status, err := r.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{}); err == nil || status != identitypostgres.RecoveryUnknown {
		t.Fatal("zero recovery admitted")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Schema = "public" },
		func(c *Config) { c.PolicyVersion = 0 },
		func(c *Config) { c.EvidenceKeys = nil },
		func(c *Config) { c.EvidenceKeys = []risk.EvidenceKey{{}} },
		func(c *Config) { c.EvidenceKeys = []risk.EvidenceKey{key, key} },
		func(c *Config) { c.CurrentEnvelopeKey = "missing" },
	} {
		bad := cfg
		mutate(&bad)
		if _, err := NewRepository(bad); err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
	// Configuration must be copied, not mutable caller-owned execution policy.
	cfg.EvidenceKeys[0] = risk.EvidenceKey{}
	clear(cfg.EnvelopeKeys["wrapping_v1"])
	if _, err := restoreCommand(cmd, r.keys, 3); err != nil {
		t.Fatal("aliased configuration", err)
	}
	if r.Descriptor().Owner != "identity/risk/postgres" || len(r.FeatureOperations()) != 1 || r.FeatureOperations()[0] != IssueOperation() {
		t.Fatal("unsupported operations advertised")
	}
	plan := identitypostgres.CommandPlan{SubjectType: "risk_evidence", Feature: &identitypostgres.FeatureRegistration{Contributor: r.Descriptor(), Operation: IssueOperation()}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "risk.evidence_issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.risk.decide", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "protected", RetentionPolicyVersion: 1}}}
	if err := r.ValidateFeatureCommand(cmd, plan); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identitypostgres.CommandPlan){
		func(p *identitypostgres.CommandPlan) { p.SubjectType = "user" },
		func(p *identitypostgres.CommandPlan) { p.Feature.Contributor.Version++ },
		func(p *identitypostgres.CommandPlan) { p.Feature.Operation.SchemaVersion++ },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.EventType = "risk.policy_changed.v1" },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.BeforeVersion = 1 },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.AfterVersion = 2 },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].EventType = "identity.risk.override" },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].Required = false },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].RetentionPolicyVersion = 0 },
	} {
		p := plan
		f, l := *plan.Feature, *plan.Lifecycle
		p.Feature, p.Lifecycle = &f, &l
		p.Audits = append([]identitypostgres.AuditPlan(nil), plan.Audits...)
		mutate(&p)
		if r.ValidateFeatureCommand(cmd, p) == nil {
			t.Fatal("unsafe native plan admitted")
		}
	}
}

func wrappingKey(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestRepositoryCustodyConfigurationCannotLeakThroughDiagnostics(t *testing.T) {
	_, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	cfg := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(0xaa)}, CurrentEnvelopeKey: "wrapping_v1"}
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{cfg, r} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if !strings.Contains(fmt.Sprintf(format, value), "redacted") {
				t.Fatal("custody diagnostic not redacted")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("custody object serializable")
		}
	}
}
