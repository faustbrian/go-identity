//go:build integration

package mfapostgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	password "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	outbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// Native operation/policy admission are fixture seams, not
// the public MFA service. Storage, kernel journal, audit, borrowed encrypted
// factor verification and child non-consumption use actual implementations.
type totpAttemptPhase struct {
	command    identity.Command
	child      kernel.CapabilityPlan
	completion kernel.MFACompletionPlan
	snapshot   TOTPFactorSnapshot
	secret     password.Secret
	verifier   mfa.TOTPVerifier
	calls      int
	retained   LockedTOTPAttempt
}

func (*totpAttemptPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *totpAttemptPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *totpAttemptPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *totpAttemptPhase) ValidateMFACompletion(c identity.Command, child kernel.CapabilityPlan, scope kernel.MFACompletionPlan) error {
	if c != p.command || child != p.child || scope != p.completion {
		return identity.ForbiddenError{}
	}
	return nil
}
func (*totpAttemptPhase) ApplyFeature(context.Context, kernel.Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, identity.ForbiddenError{}
}
func (*totpAttemptPhase) CheckFeatureCommit(context.Context, kernel.Work, identity.Command) error {
	return identity.ForbiddenError{}
}
func (*totpAttemptPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

// The declaration requires the native retained-admission interface. This
// denial-only fixture never generates/restores a successful completion; every
// unavailable phase fails closed rather than fabricating admission or output.
func (p *totpAttemptPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (*totpAttemptPhase) AdmitFeaturePreparation(context.Context, kernel.Work, identity.Command) error {
	return identity.ForbiddenError{}
}
func (*totpAttemptPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (*totpAttemptPhase) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, kernel.CommandPlan, error) {
	return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
}
func (*totpAttemptPhase) PrepareFeatureAdmission(context.Context, identity.Command) (kernel.FeaturePreparationAdmission, error) {
	return nil, identity.ForbiddenError{}
}
func (*totpAttemptPhase) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (kernel.FeaturePreparationAdmission, error) {
	return nil, identity.ForbiddenError{}
}
func (p *totpAttemptPhase) RecordMFATOTPAttemptDenial(ctx context.Context, w kernel.MFATOTPAttemptWork) (kernel.MFAAttemptDisposition, error) {
	p.calls++
	a, err := LockTOTPAttempt(ctx, w, p, p.snapshot)
	if err != nil {
		return 0, err
	}
	p.retained = a
	m, now, err := a.VerificationState()
	if err != nil {
		return 0, err
	}
	command, err := w.NativeCommand(p)
	if err != nil {
		return 0, err
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return 0, identity.ForbiddenError{}
	}
	if _, err = p.verifier.Verify(ctx, p.secret, code, m.Profile, []byte("fixture/native-attempt/key-version-1"), now, m.Replay); err == nil {
		return kernel.MFAAttemptUnchanged, nil
	}
	if err = RecordTOTPAttemptDenial(ctx, w, p, a); err != nil {
		return 0, err
	}
	if RecordTOTPAttemptDenial(ctx, w, p, a) == nil {
		return 0, identity.UnavailableError{}
	}
	return kernel.MFAAttemptDenied, nil
}

func testNativeTOTPAttempt(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpg.IdentityContributor, lifecycle *outbox.Contributor, proof capability.Proof, capabilityIssuer *capabilitypg.Issuer, issuer, factorID string, crypto *envelope.Service, expectedChild kernel.CapabilityPlan) {
	t.Helper()
	grant, _, replayVersion, err := capabilityIssuer.ReadIssuanceOrigin(ctx, pool, proof, "identity.mfa.complete")
	if err != nil {
		t.Fatal("original MFA issuance unavailable", err)
	}
	reader, err := NewTOTPFactorReader(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Read(ctx, grant, issuer, factorID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := snapshot.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	encryptionContext, err := snapshot.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: encryptionContext})
	if err != nil {
		t.Fatal("factor unavailable")
	}
	secret, err := password.NewSecret(plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	verifier, err := mfa.NewTOTPVerifier([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := reader.continuation.Read(ctx, grant, issuer)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := continuation.Bindings()
	digest, _ := continuation.ScopeDigest()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: id, TenantID: s.TenantID, AnonymousFlowID: string(s.SourcePreAuthID), ActorID: "mfa-actor", ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: "mfa-attempt"}
	child, err := capabilityIssuer.PrepareMFAConsumption(ctx, b, identity.UserID(s.SubjectID), identity.CommandID(s.ID), digest, issuer, proof, grant.EnvelopeDigest(), replayVersion)
	if err != nil || child != expectedChild {
		t.Fatal("original MFA child consumption replaced", err)
	}
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	// Six digits can never match the enrolled eight-digit profile; no clock
	// boundary or accidental random match can turn this denial test successful.
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeatureOneTimeCodeCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: child.CapabilityID}}}}, code)
	if err != nil {
		t.Fatal(err)
	}
	completion := kernel.MFACompletionPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, ContinuationVersion: s.Version}
	phase := &totpAttemptPhase{command: command, child: child, completion: completion, snapshot: snapshot, secret: secret, verifier: verifier}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, phase, capabilitypg.NewParticipant()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
	if err != nil {
		t.Fatal(err)
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
	if err != nil {
		t.Fatal(err)
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	auditDigest, err := kernel.FeatureAuditBindingDigest(b, op, "authentication_attempt", record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.PrepareMFATOTPAttemptPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: auditDigest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Capability: &child, MFACompletion: &completion})
	if err != nil {
		t.Fatal("prepare native attempt", err)
	}
	result, err := c.RecordMFATOTPAttemptDenial(ctx, b, command, plan)
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted || phase.calls != 1 {
		t.Fatal("native denial not recorded", result.Outcome, err)
	}
	replay, err := c.RecordMFATOTPAttemptDenial(ctx, b, command, plan)
	if err != nil || !reflect.DeepEqual(replay, result) || phase.calls != 1 {
		t.Fatal("replay charged again", err)
	}
	spec, _ := command.Feature()
	changedCode, e := auth.NewOneTimeCode("654321")
	if e != nil {
		t.Fatal(e)
	}
	changed, e := identity.NewFeatureOneTimeCodeCommand(spec, changedCode)
	if e != nil {
		t.Fatal(e)
	}
	phase.command = changed
	changedPlan, e := c.PrepareMFATOTPAttemptPlan(b, changed, plan)
	if e != nil {
		t.Fatal(e)
	}
	conflict, e := c.RecordMFATOTPAttemptDenial(ctx, b, changed, changedPlan)
	if e == nil || conflict.Outcome != identity.CommitOutcomeConflict || phase.calls != 1 {
		t.Fatal("changed code reused original accounting", e)
	}
	phase.command = command
	if _, _, err = phase.retained.VerificationState(); err == nil {
		t.Fatal("returned native callback retained factor authority")
	}
	var remaining, uses int32
	var state int16
	var last *string
	var journal string
	if err = pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,c.state,t.last_step::text,k.uses,j.state FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id JOIN public.capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.command_id=$4 WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, string(s.TenantID), string(s.ID), factorID, mustContinuationCommandBytes(string(id))).Scan(&remaining, &state, &last, &uses, &journal); err != nil {
		t.Fatal(err)
	}
	if remaining != int32(s.AttemptsRemaining-1) || mfa.ContinuationState(state) != mfa.Challenged || last != nil || uses != 0 || journal != "aborted" {
		t.Fatal("denial split accounting or consumed factor/child")
	}
}
