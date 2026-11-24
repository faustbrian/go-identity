//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// The journal and signed capability are real. This native fixture substitutes
// the installed provider's signer and envelope, which the go-sso journey owns.
type samlLogoutRelayIssuePreparationSQL struct {
	samlLogoutRelayIssuePreparationProbe
	origin, generated identity.Command
	intent            SSOSAMLLogoutRelayIssueIntent
	final             CommandPlan
	issuer            *issuanceSQLPhase
	grant             capability.Grant
	wire              []byte
	generations       int
	applyStage        string
}

func (p *samlLogoutRelayIssuePreparationSQL) AdmitFeaturePreparation(ctx context.Context, w Work, original identity.Command) error {
	b, registration, _, err := w.FeatureScope(p)
	spec, _ := original.Feature()
	if err != nil || original != p.origin || b != spec.Binding || registration.Operation != spec.Operation {
		return identity.ForbiddenError{}
	}
	_, err = w.DatabaseTime(ctx)
	return err
}

func (p *samlLogoutRelayIssuePreparationSQL) PrepareFeatureAdmission(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
	if original != p.origin {
		return nil, identity.ForbiddenError{}
	}
	return p, nil
}

func (p *samlLogoutRelayIssuePreparationSQL) RestoreFeatureAdmission(_ context.Context, original identity.Command, _ uint64, wire []byte) (FeaturePreparationAdmission, error) {
	if original != p.origin || !bytes.Equal(wire, p.wire) {
		return nil, identity.ForbiddenError{}
	}
	return p, nil
}

func (*samlLogoutRelayIssuePreparationSQL) Check(ctx context.Context) error { return ctx.Err() }

func (p *samlLogoutRelayIssuePreparationSQL) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	p.generations++
	p.wire = append(binary.BigEndian.AppendUint64(nil, generation), p.intent.RequestDigest[:]...)
	return bytes.Clone(p.wire), ctx.Err()
}

func (p *samlLogoutRelayIssuePreparationSQL) RestoreFeaturePreparation(_ context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	if original != p.origin || len(wire) < 8 || binary.BigEndian.Uint64(wire) != generation || !bytes.Equal(wire, p.wire) {
		return identity.Command{}, CommandPlan{}, identity.ForbiddenError{}
	}
	return p.generated, p.final, nil
}

func (p *samlLogoutRelayIssuePreparationSQL) ApplyFeature(ctx context.Context, w Work, generated identity.Command) (identity.FeatureReceipt, error) {
	p.applyStage = "read output"
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil || generation == 0 || !bytes.Equal(wire, p.wire) {
		return identity.FeatureReceipt{}, invalidPreparation()
	}
	p.applyStage = "exact work"
	if err := w.RequireSSOSAMLLogoutRelayIssue(ctx, p, generated, p.intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applyStage = "stage capability"
	if err := w.StageCapabilityIssuanceFor(p.issuer, 0, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applyStage = "apply complete"
	return identity.FeatureReceipt{Operation: SSOSAMLLogoutRelayIssueOperation(), AfterVersion: 1}, nil
}

func (p *samlLogoutRelayIssuePreparationSQL) CheckFeatureCommit(ctx context.Context, w Work, generated identity.Command) error {
	p.applyStage = "final work"
	return w.RequireSSOSAMLLogoutRelayIssue(ctx, p, generated, p.intent)
}

func TestSSOSAMLLogoutRelayIssuePreparationErasesOnlyTerminalOutput(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	preparation := PreparationMigrationSource{Base: MigrationSource{}, Version: 16}
	admission := AdmissionPreparationMigrationSource{Base: preparation, Version: 17}
	counter := CounterPreparationMigrationSource{Base: admission, Version: 18}
	prior := SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: counter, Version: 19}
	history, err := (SSOSAMLLogoutRelayIssuePreparationErasureMigrationSource{Base: prior, Version: 20}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history[len(history)-5:] {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_, probe, spec, intent, plan := samlLogoutRelayIssueFixture(t)
	intent.IssuedAt = time.Now().UTC().Truncate(time.Second)
	intent.ExpiresAt = intent.IssuedAt.Add(time.Minute)
	spec.Fields, err = SSOSAMLLogoutRelayIssueFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	b, op := spec.Binding, spec.Operation
	owner := &samlLogoutRelayIssuePreparationSQL{samlLogoutRelayIssuePreparationProbe: samlLogoutRelayIssuePreparationProbe{*probe}, intent: intent,
		generated: featureCodecCommand(t, spec), issuer: &issuanceSQLPhase{}}
	initial := intent
	initial.RequestDigest = [32]byte{}
	initial.ExpiresAt = initial.ExpiresAt.Add(time.Second)
	spec.Fields, err = SSOSAMLLogoutRelayIssuePreparationFields(initial)
	if err != nil {
		t.Fatal(err)
	}
	owner.origin = featureCodecCommand(t, spec)
	reg, err := NewContributorRegistry([]Contributor{repo, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, owner, owner.issuer})
	if err != nil {
		t.Fatal(err)
	}
	plan.Contributors = reg.Descriptors()
	plan.Audits[0].BindingDigest = securityAuditScopeDigest(b, &op, plan.SubjectType, b.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	key := bytes.Repeat([]byte{1}, 32)
	signer, err := capability.NewHMACSHA256Signer("fixture-signing-key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	grant := &plan.CapabilityIssuance.Grants[0]
	grant.ExpiresAt = intent.ExpiresAt
	payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(b.UserID), Resource: b.RecordID,
		CorrelationID: b.CorrelationID, Operation: string(grant.Purpose), IssuedAt: intent.IssuedAt, NotBefore: intent.IssuedAt, ExpiresAt: intent.ExpiresAt,
		ID: grant.CapabilityID, Tenant: string(b.TenantID), MaxUses: 1}
	token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	owner.grant, err = capability.Verify(ctx, token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: payload.Issuer, Verifier: verifier}, nil
	}), capability.VerifyOptions{Issuer: payload.Issuer, Now: intent.IssuedAt, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	grant.ProofFingerprint = sha256.Sum256([]byte(token))
	owner.final = plan
	plan.Contributors, plan.CapabilityIssuance = plan.Contributors[:4], nil
	c, err := NewCoordinator(pool, reg, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		result, err := c.ExecutePreparedFeature(ctx, owner.origin, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.AfterVersion != 1 {
			var retained, attached bool
			observation := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&retained, &attached)
			t.Fatalf("attempt %d: outcome=%v error=%v; generated=%d retained=%t attached=%t owner stage=%q observation=%v", attempt+1, result.Outcome, err, owner.generations, retained, attached, owner.applyStage, observation)
		}
	}
	var erased bool
	var issues int
	err = pool.Raw().QueryRow(ctx, `SELECT preparation_profile=4 AND preparation_started_generation IS NOT NULL AND preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL,
(SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, id, string(b.CommandID)).Scan(&erased, &issues)
	if err != nil || !erased || issues != 1 || owner.generations != 1 {
		t.Fatal("terminal issue regenerated, lost original grant or retained duplicate output", erased, issues, owner.generations, err)
	}
}
