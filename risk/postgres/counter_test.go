package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func protectedConfig(t *testing.T, keys ...risk.CounterDigestKey) Config {
	t.Helper()
	pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}}
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		k, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
		keys = []risk.CounterDigestKey{k}
	}
	_, evidence := evaluatedIssue(t, risk.PhoneResetInitiation)
	return Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: keys}}
}
func protectedCommand(t *testing.T, tenant string) identity.Command {
	t.Helper()
	id, _ := identity.NewCommandID()
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change-test-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: id, TenantID: identity.TenantID(tenant), UserID: "subject", ActorID: "subject", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, RecordID: "password", CorrelationID: string(id)}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{textField("change.reason", "self")}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestNativeProtectedCounterScope(t *testing.T) {
	cfg := protectedConfig(t)
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	subject := risk.Subject{User: "subject", Session: "session", Network: "2001:db8::1"}
	original := protectedCommand(t, "counter-tenant")
	command, plan, err := r.PrepareCommandCounters(original, subject, at)
	if err != nil || plan.PolicyVersion != 3 || plan.Fingerprint == ([32]byte{}) {
		t.Fatal("protected native preparation missing", err)
	}
	if r.ValidateCommandCounters(command, plan) != nil {
		t.Fatal("native projection not reconstructable")
	}
	if r.ValidateCommandCounters(original, plan) == nil {
		t.Fatal("unbound scope admitted")
	}
	foreign := plan
	foreign.Fingerprint[0] ^= 1
	if r.ValidateCommandCounters(command, foreign) == nil {
		t.Fatal("foreign projection admitted")
	}
	subject.User = "other"
	if _, _, e := r.PrepareCommandCounters(original, subject, at); e == nil {
		t.Fatal("wrong subject admitted")
	}
	cfg.CommandCounters.Keys[0] = risk.CounterDigestKey{}
	if r.ValidateCommandCounters(command, plan) != nil {
		t.Fatal("configuration aliased")
	}
	if _, e := r.ReserveCommandCounters(context.Background(), identitypostgres.CommandCounterWork{}); e == nil {
		t.Fatal("zero Work admitted")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.PolicyVersion = 4 },
		func(c *Config) { c.CommandCounters.Policy = risk.Policy{} },
		func(c *Config) { c.CommandCounters.Keys = nil },
	} {
		bad := protectedConfig(t)
		mutate(&bad)
		if _, e := NewRepository(bad); e == nil {
			t.Fatal("inconsistent counter configuration admitted")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "other" },
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "counter.network" {
					s.Fields[i].Value.Text = "192.0.2.2"
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "counter.key-versions" {
					s.Fields[i].Value.Bytes = []byte{0, 0, 0, 8}
				}
			}
		},
	} {
		s, _ := command.Feature()
		mutate(&s)
		bad, e := identity.NewFeatureCommand(s)
		if e != nil {
			t.Fatal("invalid fixture", e)
		}
		if r.ValidateCommandCounters(bad, plan) == nil {
			t.Fatal("altered native scope admitted")
		}
	}
}

func TestNativeCountersRejectUnrepresentablePrimaryIntervals(t *testing.T) {
	for _, class := range []risk.ProfileClass{risk.CredentialMutation, risk.Privileged} {
		cfg := protectedConfig(t)
		pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}}
		for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.profile.get"} {
			a, e := cfg.CommandCounters.Policy.Admit(action)
			if e != nil {
				t.Fatal(e)
			}
			p := a.Profile
			if p.Class == class {
				p.Window = 1500 * time.Nanosecond
				p.EvidenceTTL = time.Microsecond
			}
			pc.Profiles = append(pc.Profiles, p)
		}
		policy, e := risk.NewPolicy(pc)
		if e != nil {
			t.Fatal("core fixture profile should be valid", e)
		}
		cfg.CommandCounters.Policy = policy
		if _, e := NewRepository(cfg); e == nil {
			t.Fatal("native setup accepted window PostgreSQL Work cannot represent", class)
		}
	}
}
