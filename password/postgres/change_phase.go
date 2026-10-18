package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Invocation-only custody cannot be obtained from a caller-built command. The
// kernel independently decodes all predecessor fields before locking authority.
type passwordChangePhase struct {
	owner     kernel.CredentialReplacementContributor
	service   *PasswordChangeService
	original  session.Session
	material  password.CredentialSnapshot
	record    auth.SignedReauthenticationRecord
	facts     []risk.Signal
	scope     risk.Context
	use       auth.ReauthenticationUse
	intent    kernel.CredentialReplacementIntent
	expected  identity.Command
	csrfCheck func(session.Session) error
}

// Retained preparation reconstructs a private invocation, but every Work check
// remains owned by the exact participant registered with that coordinator.
func (p *passwordChangePhase) participant() kernel.CredentialReplacementContributor {
	if p.owner != nil {
		return p.owner
	}
	return p
}

var _ kernel.CredentialReplacementContributor = (*passwordChangePhase)(nil)

func (*passwordChangePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*passwordChangePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{replacementOperation()}
}
func (p *passwordChangePhase) matches(c identity.Command) bool {
	if p == nil || p.service == nil {
		return false
	}
	want, ok := p.expected.PasswordChangeFeature()
	got, has := c.PasswordChangeFeature()
	h, b, proof, custody := c.PasswordChangeCustody()
	wh, wb, wp, retained := p.expected.PasswordChangeCustody()
	return ok && has && custody && retained && reflect.DeepEqual(want, got) && h == wh && b.Token() == wb.Token() && proof == wp && proof == p.record.Proof
}
func (p *passwordChangePhase) CredentialReplacement(c identity.Command) (kernel.CredentialReplacementIntent, error) {
	if !p.matches(c) {
		return kernel.CredentialReplacementIntent{}, password.ErrPasswordWork
	}
	return p.intent, nil
}
func (p *passwordChangePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if !p.matches(c) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != replacementOperation() || plan.SubjectType != "credential" || plan.CommandCounters == nil || plan.Capability != nil || plan.OTP != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.changed.v1" || plan.Lifecycle.BeforeVersion != p.intent.Credential.Version || plan.Lifecycle.AfterVersion != p.intent.Credential.Version+1 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != "identity.password.change" || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *passwordChangePhase) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	use := p.use
	use.ProofUse.Now = now
	if p.record.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	if _, err = p.original.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	scope := p.scope
	scope.Now = now
	decision, err := p.service.assessChangeProviders(ctx, scope, p.facts)
	if err != nil || decision.Action != risk.Allow {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *passwordChangePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || !p.matches(c) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	spec, _ := c.PasswordChangeFeature()
	b, feature, _, err := w.FeatureScope(p.participant())
	if err != nil || b != spec.Binding || feature.Operation != replacementOperation() {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	source := p.service.source
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(source.c.Profile, p.original, b)
	if err != nil || credential.Credential != p.intent.Credential || credential.CredentialAuthorityVersion != p.intent.ExpectedAuthorityVersion {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p.participant(), directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.RequireActiveCredential(ctx, p.participant(), credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveUserAuthorization(ctx, p.participant(), policy); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = sessionpg.RequireSession(ctx, w, source.c.Session, p.original); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.csrfCheck != nil {
		if err = p.csrfCheck(p.original); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err = p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.consume(ctx, w, b); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Reuse the existing closed material writer. Its public hash-only path stays
	// unchanged; only this private invocation supplies authenticated custody.
	fields, err := kernel.CredentialReplacementFields(p.intent)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	hash, _, _, _ := c.PasswordChangeCustody()
	plain, err := identity.NewFeaturePasswordHashCommand(identity.FeatureCommandSpec{Binding: b, Operation: replacementOperation(), Fields: fields}, hash)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	i, encoded, err := passwordReplacement(plain, source.repository.policy)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := source.repository.applyReplacement(ctx, w, p.participant(), identity.FeatureCommandSpec{Binding: b, Operation: replacementOperation(), Fields: fields}, i, encoded)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = p.service.sessions.Apply(ctx, w, p.participant(), c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}

func (p *passwordChangePhase) consume(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	return consumeReauthenticationRecord(ctx, w, b, p.record, p.checkTime)
}

// The named protected actions share the same password-owned record and exclusive
// consumer lock. The calling native phase must first fence its current owners;
// checkTime rechecks original expiry after waiting, never renews it.
func consumeReauthenticationRecord(ctx context.Context, w kernel.Work, b identity.CommandBinding, record auth.SignedReauthenticationRecord, checkTime func(context.Context, kernel.Work) error) error {
	if ctx == nil || checkTime == nil || record.Proof.Proof.Tenant != string(b.TenantID) || record.Proof.Proof.Subject != string(b.UserID) || record.Proof.Action != b.OperationID || !reauthenticationConsumptionAction(b.OperationID) {
		return identity.ForbiddenError{}
	}
	expected, err := encodeReauthenticationRecord(record)
	if err != nil {
		return err
	}
	defer clear(expected)
	rows, err := w.Query(ctx, `SELECT CASE WHEN octet_length(p.record)<=$4 THEN p.record ELSE ''::bytea END,p.consumed_command_id IS NULL
FROM identity_password.reauthentication_records p JOIN identity.commands c USING(tenant_id,purpose,command_id)
WHERE p.proof_id=$1 AND p.tenant_id=$2 AND p.user_id=$3 AND c.state='committed' FOR UPDATE OF p`, string(record.Proof.Proof.ID), string(b.TenantID), string(b.UserID), maximumReauthenticationRecordBytes)
	if err != nil {
		return err
	}
	if !rows.Next() {
		e := rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		return identity.ForbiddenError{}
	}
	var payload []byte
	var unused bool
	err = rows.Scan(&payload, &unused)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return password.ErrPasswordWork
	}
	if !unused || !bytes.Equal(payload, expected) {
		return identity.ForbiddenError{}
	}
	// Recheck original expiry after waiting for the exclusive one-use lock.
	if err = checkTime(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return password.ErrPasswordWork
	}
	n, err := w.Exec(ctx, `UPDATE identity_password.reauthentication_records SET consumed_command_id=$4,consumed_purpose=$5,consumed_at=$6 WHERE proof_id=$1 AND tenant_id=$2 AND user_id=$3 AND consumed_command_id IS NULL`, string(record.Proof.Proof.ID), string(b.TenantID), string(b.UserID), id, b.OperationID, now)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func reauthenticationConsumptionAction(action string) bool {
	switch action {
	case "identity.password.change", "identity.mfa.enable", "identity.email.verification-send", "identity.email.change-request", "identity.email.address-remove", "identity.username.update", "identity.organization.owner-transfer":
		return true
	default:
		return false
	}
}

func (p *passwordChangePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.service == nil || ctx == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	material, err := p.service.source.repository.recoverReplacement(ctx, w, p.participant())
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	sessions, err := p.service.sessions.Recover(ctx, w, p.participant())
	if err != nil || sessions != material {
		return kernel.RecoveryUnknown, err
	}
	b, _, _, err := w.FeatureScope(p.participant())
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT proof_id,user_id,CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND consumed_purpose=$2 AND consumed_command_id=$3`, string(b.TenantID), b.OperationID, id, maximumReauthenticationRecordBytes)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		if material == kernel.RecoveryNotCommitted {
			return material, nil
		}
		return kernel.RecoveryUnknown, nil
	}
	var proofID, user string
	var payload []byte
	if rows.Scan(&proofID, &user, &payload) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	record, err := decodeReauthenticationRecord(auth.ProofID(proofID), string(b.TenantID), string(b.UserID), payload)
	if err != nil || user != string(b.UserID) || record.Proof.Action != b.OperationID || record.Proof.Proof.Purpose != "identity.password.verify" || record.CredentialID != b.RecordID || material != kernel.RecoveryCommitted {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

func passwordChangePlan(c *kernel.Coordinator, r *kernel.ContributorRegistry, p *passwordChangePhase, b identity.CommandBinding, command identity.Command, counters kernel.CommandCounterPlan, now time.Time) (kernel.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	version := p.intent.Credential.Version
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(version, 10), "aggregate.after_version": strconv.FormatUint(version+1, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, replacementOperation(), "credential", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan := kernel.CommandPlan{Contributors: r.Descriptors(), SubjectType: "credential", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: replacementOperation()}, CommandCounters: &counters, Lifecycle: &kernel.LifecyclePlan{EventType: "password.changed.v1", BeforeVersion: version, AfterVersion: version + 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	return c.PrepareCommandPlan(b, command, plan)
}
