package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestNativeEvidenceUsePreparationAuthenticatesCompleteScope(t *testing.T) {
	issue, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	at := issue.Prepared().PreparedAt
	record, err := issue.Materialize(at)
	if err != nil {
		t.Fatal(err)
	}
	// Pure preparation may not dispatch any provider, executor or counter.
	issuer, original, _ := issuanceFixture(t, risk.PhoneResetInitiation, at.Add(time.Nanosecond), issue.Prepared().Binding.CommandID, captureExecutor{}, true, nil)
	id, _ := identity.NewCommandID()
	use, err := issuer.PrecheckUse(context.Background(), original, risk.EvidenceUseRequest{CommandID: string(id), Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}, record)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", UseIssuer: &issuer}
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	installedIssuer := issuer
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "subject", ActorID: "phone-service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "phone-policy", PolicyVersion: 1, RecordID: "phone-record", CorrelationID: string(id)}, Operation: op, Fields: []identity.FeatureField{textField("phone.mode", "reset")}}
	command, plan, err := r.PrepareEvidenceUse(spec, original, use)
	if err != nil || plan != nativeUsePlan(use.Prepared()) || r.ValidateRiskEvidenceCommand(command, plan) != nil {
		t.Fatal("exact scope rejected or interval changed", err)
	}
	if _, enabled := any(r).(identitypostgres.RiskExecutionContributor); !enabled {
		t.Fatal("native risk consuming phases missing")
	}
	// Caller projections and issuer variables are not retained mutable custody.
	issuer = risk.PhoneEvidenceIssuer{}
	spec.Fields[0].Value.Text = "changed"
	if err := r.ValidateRiskEvidenceCommand(command, plan); err != nil {
		t.Fatal("caller input was retained", err)
	}
	s, _ := command.Feature()
	if len(s.Fields) != 8 {
		t.Fatal("incomplete native scope")
	}
	for i, f := range s.Fields {
		if f.Name == "phone.mode" {
			continue
		}
		for _, wrongKind := range []bool{false, true} {
			changed, _ := command.Feature()
			if wrongKind {
				changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureBool}
			} else if f.Value.Kind == identity.FeatureText {
				changed.Fields[i].Value.Text += "x"
			} else {
				changed.Fields[i].Value.Bytes[0] ^= 1
			}
			bad, err := identity.NewFeatureCommand(changed)
			if err != nil {
				t.Fatal("invalid tampering setup", err)
			}
			if r.ValidateRiskEvidenceCommand(bad, plan) == nil {
				t.Fatal("changed native scope admitted", f.Name)
			}
		}
		missing, _ := command.Feature()
		missing.Fields = append(missing.Fields[:i], missing.Fields[i+1:]...)
		bad, err := identity.NewFeatureCommand(missing)
		if err != nil || r.ValidateRiskEvidenceCommand(bad, plan) == nil {
			t.Fatal("missing field admitted", f.Name, err)
		}
	}
	for _, change := range []func(*risk.PhoneEvidenceRequest){
		func(o *risk.PhoneEvidenceRequest) { o.Recovery.Binding.CanonicalNumber = "+358401234568" },
		func(o *risk.PhoneEvidenceRequest) { o.Recovery.Binding.PreAuthTransaction += "x" },
		func(o *risk.PhoneEvidenceRequest) { o.Recovery.Binding.Attempt += "x" },
		func(o *risk.PhoneEvidenceRequest) { o.Subject.Network = "2001:db8::2" },
		func(o *risk.PhoneEvidenceRequest) { o.Subject.Device += "x" },
		func(o *risk.PhoneEvidenceRequest) {
			o.Subject.IdentifierDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		func(o *risk.PhoneEvidenceRequest) { o.Subject.User = "subject" },
	} {
		bad := original
		change(&bad)
		if c, p, err := r.PrepareEvidenceUse(spec, bad, use); err == nil || c != (identity.Command{}) || p != (identitypostgres.RiskEvidencePlan{}) {
			t.Fatal("foreign original mapped")
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "other" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, textField("risk.use.number", "+358401234567"))
		},
	} {
		bad := spec
		bad.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		change(&bad)
		if _, _, err := r.PrepareEvidenceUse(bad, original, use); err == nil {
			t.Fatal("foreign consumer mapped")
		}
	}
	changedPlan := plan
	changedPlan.CheckedAt = changedPlan.CheckedAt.Add(time.Nanosecond)
	if r.ValidateRiskEvidenceCommand(command, changedPlan) == nil {
		t.Fatal("changed signed plan admitted")
	}
	unknown, _ := command.Feature()
	unknown.Fields = append(unknown.Fields, textField("risk.use.extra", "unexpected"))
	unknownCommand, err := identity.NewFeatureCommand(unknown)
	if err != nil || r.ValidateRiskEvidenceCommand(unknownCommand, plan) == nil {
		t.Fatal("unknown scope field admitted", err)
	}
	if _, _, err := r.PrepareEvidenceUse(spec, original, risk.EvidenceUse{}); err == nil {
		t.Fatal("zero precheck mapped")
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.PolicyVersion++ },
		func(c *Config) { c.EvidenceKeys = append(c.EvidenceKeys, risk.EvidenceKey{}) },
		func(c *Config) {
			k, e := risk.NewEvidenceKey(1, wrappingKey(0x43), wrappingKey(0x42))
			if e != nil {
				t.Fatal(e)
			}
			c.EvidenceKeys = []risk.EvidenceKey{k}
		},
		func(c *Config) {
			k, e := risk.NewEvidenceKey(1, wrappingKey(0x41), wrappingKey(0x43))
			if e != nil {
				t.Fatal(e)
			}
			c.EvidenceKeys = []risk.EvidenceKey{k}
		},
	} {
		bad := cfgWithIssuer(cfg, &installedIssuer)
		bad.EvidenceKeys = append([]risk.EvidenceKey(nil), cfg.EvidenceKeys...)
		change(&bad)
		if _, err := NewRepository(bad); err == nil {
			t.Fatal("mismatched native issuer custody admitted")
		}
	}
	for _, native := range []*Repository{nil, {}, func() *Repository {
		cfg.UseIssuer = nil
		n, e := NewRepository(cfg)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}()} {
		if native.ValidateRiskEvidenceCommand(command, plan) == nil {
			t.Fatal("disabled use admitted")
		}
		if _, _, err := native.PrepareEvidenceUse(spec, original, use); err == nil {
			t.Fatal("disabled preparation admitted")
		}
	}
	// The original config now points at a zero issuer and must fail setup.
	if _, err := NewRepository(cfgWithIssuer(cfg, &issuer)); err == nil {
		t.Fatal("zero issuer admitted")
	}
}

func cfgWithIssuer(c Config, i *risk.PhoneEvidenceIssuer) Config { c.UseIssuer = i; return c }
