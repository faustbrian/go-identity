package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
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

// Reset is an Authentication operation in the canonical risk matrix. Its
// counted admission runs before credential/HIBP work, not against a fabricated
// authenticated session. Native preparation must retain that original admission.
func TestResetAuthenticationPreparationPreservesAtomicConsumption(t *testing.T) {
	c, p, _ := resetPlanFixture(t)
	s, _ := c.PasswordResetFeature()
	p.CommandCounters = nil
	p.Contributors = append(p.Contributors[:4:4], p.Contributors[5])
	wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal("counted Authentication reset cannot use original preparation", err)
	}
	got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire)
	if err != nil || got.CommandCounters != nil || *got.Capability != *p.Capability || got.Digest != sha256.Sum256(wire) {
		t.Fatal("reset lost original consumption declaration", err)
	}
	if preparationProtected(p) || !preparationFinalDeclaration(s.Binding, p, p) {
		t.Fatal("original reset cannot preserve proof consumption through hash preparation")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Capability = nil },
		func(p *CommandPlan) { p.Capability.ReplayKeyVersion++ },
		func(p *CommandPlan) { p.Capability.CapabilityID = "foreign" },
		func(p *CommandPlan) { p.Capability.ReplayDigest[0] ^= 1 },
		func(p *CommandPlan) { p.Capability.ProofFingerprint[0] ^= 1 },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		func(p *CommandPlan) { p.Capability.MaxUses++ },
		func(p *CommandPlan) { p.Capability.Purpose = "identity.identifier.verify" },
		func(p *CommandPlan) {
			p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{5}}
		},
		func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
	} {
		final := p
		capability := *p.Capability
		final.Capability = &capability
		change(&final)
		if preparationFinalDeclaration(s.Binding, p, final) {
			t.Fatal("hash generation changed original reset consumption or added effects")
		}
	}
}

type resetAdmissionCheck struct{ err error }

func TestResetAuthenticationInputBindsPasswordBeforeHashing(t *testing.T) {
	c, _, _ := resetPlanFixture(t)
	s, _ := c.PasswordResetFeature()
	_, proof, _ := c.PasswordResetCustody()
	secret, err := primitive.NewSecret([]byte(" original reset\x00\xffcandidate "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	input, err := identity.NewFeaturePasswordResetInputCommand(s, secret, proof)
	if err != nil {
		t.Fatal("original ungenerated reset input denied", err)
	}
	q, err := prepareClaim(input, [32]byte{1})
	if err != nil || bytes.Contains(q.canonical, []byte("original reset")) || bytes.Contains(q.safeFields, []byte("original reset")) {
		t.Fatal("original reset input not safely bound", err)
	}
	if _, ok := input.Feature(); ok {
		t.Fatal("legacy metadata discarded original password/proof")
	}
	if _, ok := input.PasswordResetFeature(); ok {
		t.Fatal("original input selected as generated reset verifier")
	}
	borrowed, originalProof, ok := input.PasswordResetInputCustody()
	if !ok || borrowed.Len() != secret.Len() || originalProof.ValidateBounds(32, 4096) != nil {
		t.Fatal("borrowed original reset custody lost")
	}
	for _, raw := range [][]byte{[]byte("original reset\x00\xffcandidate"), []byte(" different password ")} {
		changed, err := primitive.NewSecret(raw)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(changed.Destroy)
		other, err := identity.NewFeaturePasswordResetInputCommand(s, changed, proof)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := prepareClaim(other, [32]byte{1})
		if err != nil || bytes.Equal(claim.canonical, q.canonical) || !bytes.Equal(claim.safeFields, q.safeFields) {
			t.Fatal("changed raw password reused original claim", err)
		}
	}
	generated, err := prepareClaim(c, [32]byte{1})
	if err != nil || bytes.Equal(generated.canonical, q.canonical) {
		t.Fatal("generated verifier reused plaintext preparation domain", err)
	}
	secret.Destroy()
	if _, err := prepareClaim(input, [32]byte{1}); err == nil {
		t.Fatal("destroyed original password acquired new claim")
	}
	if _, ok := input.PasswordResetInputFeature(); !ok {
		t.Fatal("password destruction erased safe original metadata")
	}
}

func (a resetAdmissionCheck) Check(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return a.err
}
func (resetAdmissionCheck) Generate(context.Context, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}

func TestResetAuthenticationCannotExecuteWithoutOriginalAdmission(t *testing.T) {
	for _, missing := range []string{"preparation", "admission", "output", "generation", "execution"} {
		w, _ := preparationOutputFixture(t)
		p := w.state.execution.reservation.plan
		p.feature.Operation = credentialResetOperation()
		w.state.execution.reservation.preparation.admission = resetAdmissionCheck{}
		switch missing {
		case "preparation":
			w.state.execution.reservation.preparation = nil
		case "admission":
			w.state.execution.reservation.preparation.admission = nil
		case "output":
			w.state.execution.reservation.preparation.ciphertext = nil
		case "generation":
			w.state.execution.reservation.preparation.generation = 0
		case "execution":
			w.state.execution.reservation.executionRequest = nil
		}
		if w.state.execution.coordinator.checkPreparedAdmission(w) == nil {
			t.Fatalf("reset executed without original %s", missing)
		}
	}
	w, _ := preparationOutputFixture(t)
	w.state.execution.reservation.plan.feature.Operation = credentialResetOperation()
	w.state.execution.reservation.preparation.admission = resetAdmissionCheck{}
	if err := w.state.execution.coordinator.checkPreparedAdmission(w); err != nil {
		t.Fatal("original admitted reset denied", err)
	}
	w.state.execution.reservation.preparation.admission = resetAdmissionCheck{err: identity.ForbiddenError{}}
	if w.state.execution.coordinator.checkPreparedAdmission(w) == nil {
		t.Fatal("expired or denied original reset admission ignored")
	}
	// Existing non-reset ordinary features remain source/behavior compatible.
	w, _ = preparationOutputFixture(t)
	w.state.execution.reservation.preparation = nil
	if err := w.state.execution.coordinator.checkPreparedAdmission(w); err != nil {
		t.Fatal("ordinary feature acquired reset-only admission requirement", err)
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
