package passwordpostgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This invocation-local owner is intentionally private. Neither public
// comparison output nor a caller-constructed proof can supply live custody.
type reauthenticationPhase struct {
	service   *ReauthenticationService
	original  session.Session
	material  password.CredentialSnapshot
	admission risk.AuthenticationAdmission
	record    auth.SignedReauthenticationRecord
	expected  identity.Command
	csrf      *reauthenticationCSRF
}

var _ kernel.FeatureExecutionContributor = (*reauthenticationPhase)(nil)

func (*reauthenticationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password.reauthentication", Version: 1}
}
func (*reauthenticationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{reauthenticationOperation()}
}
func reauthenticationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.verify", SchemaID: "password-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (p *reauthenticationPhase) command(b identity.CommandBinding, bearer auth.BearerCredential) (identity.Command, error) {
	fields, err := sessionpg.OriginalSessionFields(p.original)
	if err != nil {
		return identity.Command{}, err
	}
	proof := p.record.Proof
	text := func(name, value string) {
		fields = append(fields, identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}})
	}
	number := func(name string, value uint64) {
		fields = append(fields, identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}})
	}
	text("proof.id", string(proof.Proof.ID))
	text("proof.purpose", string(proof.Proof.Purpose))
	text("proof.action", proof.Action)
	text("proof.audience", proof.Proof.Audience)
	text("proof.issuer", p.record.Issuer)
	text("proof.environment", p.record.Environment)
	text("proof.key", p.record.KeyID)
	text("proof.method", proof.Proof.Method)
	// Decimal seconds and nanos preserve upstream nanosecond instants without
	// coercing them into the kernel's microsecond-only FeatureTime variant.
	text("proof.issued", proof.Proof.IssuedAt.UTC().Format(time.RFC3339Nano))
	text("proof.expires", proof.Proof.ExpiresAt.UTC().Format(time.RFC3339Nano))
	number("proof.version", p.record.ProofVersion)
	number("proof.assurance", uint64(proof.Proof.Assurance))
	fields = append(fields, identity.FeatureField{Name: "proof.signature", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.record.Signature}})
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: reauthenticationOperation(), Fields: fields}, bearer)
}

func (p *reauthenticationPhase) matches(c identity.Command) bool {
	want, ok := p.expected.Feature()
	got, exists := c.Feature()
	token, possession := c.SessionToken()
	expected, has := p.expected.SessionToken()
	return ok && exists && possession && has && reflect.DeepEqual(want, got) && token.Token() == expected.Token()
}

func (p *reauthenticationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || !p.matches(c) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != reauthenticationOperation() || plan.SubjectType != "proof" || plan.Capability != nil || plan.OTP != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.verified.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != "identity.password.verify" || !a.Required || a.RequiredRecordCount != 1 || a.SchemaVersion != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *reauthenticationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.service == nil || ctx == nil || !p.matches(c) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	b, feature, transition, err := w.FeatureScope(p)
	spec, _ := c.Feature()
	if err != nil || b != spec.Binding || feature.Operation != reauthenticationOperation() || transition.EventType != "password.verified.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.c.Profile, p.original, b)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	observed := p.material.Authority()
	if observed.Credential != credential.Credential || observed.AuthorityVersion != credential.CredentialAuthorityVersion {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err = p.admission.Check(ctx); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.RequireActiveCredential(ctx, p, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.csrf != nil {
		key, e := p.csrf.key(p.original)
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
		err = sessionpg.RequireCSRF(ctx, w, p.service.c.Session, p.original, p.csrf.token, key)
	} else {
		err = sessionpg.RequireSession(ctx, w, p.service.c.Session, p.original)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	rows, err := w.Query(ctx, `SELECT version::text,CASE WHEN octet_length(encoded_hash)<=$4 THEN encoded_hash ELSE '' END FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR SHARE`, string(b.TenantID), string(b.UserID), string(credential.Credential.ID), p.service.repository.limits.EncodedHashBytes)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var version, hash string
	if !rows.Next() {
		e := rows.Err()
		rows.Close()
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	err = rows.Scan(&version, &hash)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if version != strconv.FormatUint(credential.Credential.Version, 10) || hash != p.material.EncodedHash().String() {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err = p.currentTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	payload, err := encodeReauthenticationRecord(p.record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_password.reauthentication_records(proof_id,tenant_id,user_id,command_id,purpose,record) VALUES($1,$2,$3,$4,$5,$6)`, string(p.record.Proof.Proof.ID), string(b.TenantID), string(b.UserID), id, b.OperationID, payload)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err = p.currentTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *reauthenticationPhase) currentTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	proof := p.record.Proof.Proof
	if now.Before(proof.IssuedAt) || !now.Before(proof.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if _, err = p.original.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	return p.admission.Check(ctx)
}

func (p *reauthenticationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.service == nil || ctx == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	b, feature, transition, err := w.FeatureScope(p)
	if err != nil || feature.Operation != reauthenticationOperation() || transition.EventType != "password.verified.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT proof_id,CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND purpose='identity.password.verify' AND command_id=$3`, string(b.TenantID), string(b.UserID), id, maximumReauthenticationRecordBytes)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var proofID string
	var payload []byte
	if rows.Scan(&proofID, &payload) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	r, err := decodeReauthenticationRecord(auth.ProofID(proofID), string(b.TenantID), string(b.UserID), payload)
	if err != nil || proofID != b.RecordID || proofID != string(b.CommandID) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	key := p.service.c.VerificationKeys[r.KeyID]
	frame, err := r.SigningBytes()
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Signature) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryCommitted, nil
}

func reauthenticationPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, p *reauthenticationPhase, b identity.CommandBinding, c identity.Command, now time.Time) (kernel.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	op := reauthenticationOperation()
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "proof", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "proof", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "proof", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "proof", Lifecycle: &kernel.LifecyclePlan{EventType: "password.verified.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
