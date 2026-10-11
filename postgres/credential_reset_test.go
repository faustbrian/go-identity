package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func resetPlanFixture(t *testing.T) (identity.Command, CommandPlan, CredentialResetIntent) {
	t.Helper()
	i := CredentialResetIntent{Replacement: replacementIntentFixture(), ExpectedEnabled: true}
	s := passwordResetCodecSpec()
	c := i.Replacement.Credential
	s.Binding.TenantID, s.Binding.UserID, s.Binding.RecordID = c.TenantID, c.UserID, string(c.ID)
	var err error
	s.Fields, err = CredentialResetFields(i)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := passwordResetCodecProof(t, 1)
	command := passwordResetCodecCommand(t, s, "synthetic", proof)
	_, _, p := featurePlanFixture(t)
	p.Feature = &FeatureRegistration{Operation: s.Operation, Contributor: ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType = "credential"
	p.Lifecycle = &LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: c.Version, AfterVersion: c.Version + 1}
	p.Audits[0].RetentionClass = "protected"
	p.Audits[0].EventType = "identity.password.reset-complete"
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{5}}
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}, ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
	p.Capability = &CapabilityPlan{CapabilityID: "synthetic-reset", Purpose: "identity.password.reset-complete", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{4}, ExpiresAt: time.Unix(1800000000, 0).UTC(), MaxUses: 1}
	return command, p, i
}

func TestCredentialResetPlanRoundTripAndClosedProfile(t *testing.T) {
	c, p, _ := resetPlanFixture(t)
	s, _ := c.PasswordResetFeature()
	wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal("reset atomic declaration rejected", err)
	}
	got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire)
	if err != nil || got.Digest != sha256.Sum256(wire) || *got.Capability != *p.Capability || got.Feature.Operation != s.Operation {
		t.Fatal("reset history lost original binding", err)
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"missing proof":       func(p *CommandPlan) { p.Capability = nil },
		"missing counters":    func(p *CommandPlan) { p.CommandCounters = nil },
		"OTP":                 func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		"risk substitution":   func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		"new issuance":        func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"new delivery":        func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"email purpose":       func(p *CommandPlan) { p.Capability.Purpose = "identity.identifier.verify" },
		"reusable":            func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		"missing fingerprint": func(p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		"unprotected":         func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"change event":        func(p *CommandPlan) { p.Lifecycle.EventType = "password.changed.v1" },
		"change operation":    func(p *CommandPlan) { p.Feature.Operation.OperationID = "identity.password.change" },
		"foreign adapter":     func(p *CommandPlan) { p.Feature.Contributor.ContractID = "foreign" },
		"foreign subject":     func(p *CommandPlan) { p.SubjectType = "identifier" },
		"missing cap owner":   func(p *CommandPlan) { p.Contributors = p.Contributors[:len(p.Contributors)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			_, p, _ := resetPlanFixture(t)
			mutate(&p)
			if _, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p); err == nil {
				t.Fatal("foreign reset profile admitted")
			}
		})
	}
	for idx := range wire {
		if _, err := decodeFeaturePlan(s.Binding, [32]byte{1}, bytes.Clone(wire[:idx])); err == nil {
			t.Fatal("truncated reset history decoded")
		}
	}
}

func FuzzCredentialResetPlan(f *testing.F) {
	for _, seed := range [][]byte{{}, {0xa5}, {0xa5, 0x64, 'b', 'a', 's', 'e', 0x41, 0xa9}, bytes.Repeat([]byte{0xff}, 32)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65537 {
			return
		}
		command, plan, _ := resetPlanFixture(t)
		s, _ := command.PasswordResetFeature()
		if len(data) == 0 {
			var err error
			data, err = encodeFeaturePlan(s.Binding, [32]byte{1}, plan)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := decodeCredentialResetPlan(s.Binding, [32]byte{1}, data)
		if err != nil {
			return
		}
		canonical, err := encodeCredentialResetPlan(s.Binding, [32]byte{1}, got)
		if err != nil || !bytes.Equal(canonical, data) || got.Digest != sha256.Sum256(data) {
			t.Fatal("reset decoder admitted noncanonical retained history")
		}
	})
}

type resetMappingPhase struct {
	FeatureCommitContributor
	intent CredentialResetIntent
	err    error
}

func (p resetMappingPhase) CredentialReset(identity.Command) (CredentialResetIntent, error) {
	return p.intent, p.err
}

func TestCredentialResetIntentRequiresDistinctNativeAuthority(t *testing.T) {
	c, p, i := resetPlanFixture(t)
	native := resetMappingPhase{intent: i}
	if got, err := credentialResetCommand(native, c, p); err != nil || got != i {
		t.Fatal("exact reset mapping denied", err)
	}
	for _, mutate := range []func(*CommandPlan, *resetMappingPhase){
		func(_ *CommandPlan, n *resetMappingPhase) { n.intent.ExpectedEnabled = false },
		func(_ *CommandPlan, n *resetMappingPhase) { n.intent.Replacement.ExpectedAuthorityVersion++ },
		func(p *CommandPlan, _ *resetMappingPhase) { p.Capability = nil },
		func(p *CommandPlan, _ *resetMappingPhase) { p.Lifecycle.AfterVersion++ },
		func(p *CommandPlan, _ *resetMappingPhase) { p.Lifecycle.EventType = "password.changed.v1" },
	} {
		_, p, i := resetPlanFixture(t)
		n := resetMappingPhase{intent: i}
		mutate(&p, &n)
		if _, err := credentialResetCommand(n, c, p); err == nil {
			t.Fatal("foreign reset authority admitted")
		}
	}
	s, _ := c.PasswordResetFeature()
	if _, err := credentialResetCommand(native, featureCodecCommand(t, s), p); err == nil {
		t.Fatal("generic reset metadata acquired authority")
	}
	if _, err := replacementCommand(replacementMappingPhase{intent: i.Replacement}, c, p); err == nil {
		t.Fatal("reset borrowed change admission")
	}
	i.ExpectedEnabled = false
	s.Fields, _ = CredentialResetFields(i)
	proof, _ := passwordResetCodecProof(t, 1)
	disabled := passwordResetCodecCommand(t, s, "synthetic", proof)
	if got, err := credentialResetCommand(resetMappingPhase{intent: i}, disabled, p); err != nil || got.ExpectedEnabled {
		t.Fatal("explicit disabled recovery scope lost", err)
	}
}

func TestCredentialResetMigrationPreservesInstalledChangeHistory(t *testing.T) {
	base := CredentialReplacementMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, err := (CredentialResetMigrationSource{Base: base, Version: 15}).Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("reset history unavailable", err)
	}
	for idx := range before {
		if before[idx].Checksum() != after[idx].Checksum() {
			t.Fatal("installed change migration rewritten")
		}
	}
	for _, s := range []CredentialResetMigrationSource{{}, {Base: base}, {Base: base, Version: 14}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if rows, err := s.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("invalid reset migration returned history")
		}
	}
}
