package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// Config selects the dedicated migrated namespace, current risk policy and
// retained core signing/digest keys. EvidenceKeys must be the issuer's exact
// retained key set. Envelope keys are nonzero local AES-256 keys, indexed by
// stable references; retain every reference needed by historical responses.
// Construction copies all keys. Zero and unsupported configuration fail closed.
type Config struct {
	Schema             string
	PolicyVersion      uint64
	EvidenceKeys       []risk.EvidenceKey
	EnvelopeKeys       map[string][]byte
	CurrentEnvelopeKey string
	// CommandCounters optionally enables only native protected command counters.
	// Nil preserves issuance-only setup. All retained keys are copied; removal
	// requires durable retirement, which this initial profile does not yet expose.
	CommandCounters *risk.CommandCounterPolicyConfig
	// EnforceLockouts selects current durable lockout admission for protected
	// command counters. Install LockoutMigrationSource first. False preserves the
	// earlier counter-only development profile, not complete risk enforcement.
	// It cannot start/end a lockout, select a duration or bypass safe recovery.
	EnforceLockouts bool
	// LockoutMutations enables native authorized start/end. Install
	// LockoutStateMigrationSource, LockoutTransitionMigrationSource and the
	// authorization owner's authority schema before selection. Nil preserves
	// the interval-only development profile.
	LockoutMutations *LockoutMutationConfig
	// UseIssuer optionally installs pure original-scope authentication for native
	// use preparation. It must match PolicyVersion and every retained EvidenceKey.
	// The issuer value is copied; nil preserves reservation-only setup. Current
	// execution additionally requires UseCounters and the original durable rows.
	UseIssuer *risk.PhoneEvidenceIssuer
	// UseCounters selects the same durable counter owner used by phone evidence
	// issuance. Install DurableCounterMigrationSource first. Current use reads
	// its existing scope, original authenticated attempt and current windows
	// through the sole Risk Work, never its pool or a second transaction. The
	// store's immutable custody is borrowed; its pool remains caller-owned.
	// Nil preserves pure preparation/reservation, but domain use fails closed.
	UseCounters *DurableCounterStore
	// CaptchaCustody selects 1..32 immutable current verifier profiles for native
	// CAPTCHA issuance and current consuming phases. Nil preserves existing setup.
	// Every profile must match
	// PolicyVersion and the complete retained EvidenceKeys. Install the separately
	// allocated CaptchaMigrationSource and CaptchaScopeMigrationSource before
	// issuance; also install CaptchaUseMigrationSource for consuming reservation.
	// No provider callbacks
	// are retained or invoked by this durable owner.
	CaptchaCustody []risk.CaptchaEvidenceCustody
}

// Format redacts copied and caller-owned key material in all diagnostics.
func (Config) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "postgres.Config(redacted)") }

// MarshalJSON rejects secret-bearing startup configuration serialization.
func (Config) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects secret-bearing startup configuration serialization.
func (Config) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// Repository owns issued-evidence SQL through the sole identity coordinator.
// It has no transaction, connection or bearer-read API. It is immutable and
// safe for concurrent independent invocations; Work remains serial-use only.
// Zero is invalid. Initiation reservation/rebind use the sole coordinator;
// consuming recovery and terminal release use that coordinator as well.
// Protected counters, authorized native lockout transitions and native CAPTCHA
// issuance and consuming custody are opt-in. CAPTCHA check/finalize and proven
// terminal release run through the same coordinator. Phone use additionally
// needs exact issuer/durable-counter custody; the phone workflow still owns
// domain/factor authority. Counter retirement and pruning remain unsupported.
// Selection is not a complete consumer workflow service.
type Repository struct {
	schema          string
	policy          uint64
	keys            []risk.EvidenceKey
	cipher          recordCipher
	counters        *risk.CommandCounterPolicyConfig
	counterPolicy   risk.CommandCounterPolicy
	useIssuer       *risk.PhoneEvidenceIssuer
	useCounters     *durableCounterState
	lockouts        bool
	lockoutMutation *lockoutMutationState
	captcha         []risk.CaptchaEvidenceCustody
}

// Format hides runtime custody configuration and retained key material.
func (Repository) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.Repository(redacted)")
}

// MarshalJSON rejects serialization of runtime custody state.
func (Repository) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects serialization of runtime custody state.
func (Repository) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

var _ identitypostgres.FeatureExecutionContributor = (*Repository)(nil)

// NewRepository validates and copies local custody configuration without IO.
// The returned instance must be enlisted in the same coordinator registry used
// by execution and recovery; matching descriptor names do not confer authority.
func NewRepository(c Config) (*Repository, error) {
	if c.EnforceLockouts && c.CommandCounters == nil {
		return nil, risk.ErrInvalidPolicy
	}
	if !validSchema(c.Schema) || c.PolicyVersion == 0 || len(c.EvidenceKeys) == 0 || len(c.EvidenceKeys) > 16 {
		return nil, risk.ErrInvalidPolicy
	}
	for i, key := range c.EvidenceKeys {
		if key == (risk.EvidenceKey{}) {
			return nil, risk.ErrInvalidPolicy
		}
		for _, previous := range c.EvidenceKeys[:i] {
			if key == previous {
				return nil, risk.ErrInvalidPolicy
			}
		}
	}
	cipher, err := newRecordCipher(c.EnvelopeKeys, c.CurrentEnvelopeKey)
	if err != nil {
		return nil, err
	}
	r := &Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), policy: c.PolicyVersion, keys: append([]risk.EvidenceKey(nil), c.EvidenceKeys...), cipher: cipher, lockouts: c.EnforceLockouts}
	if len(c.CaptchaCustody) > 32 {
		return nil, risk.ErrInvalidPolicy
	}
	for _, custody := range c.CaptchaCustody {
		if custody.ValidateConfiguration(c.PolicyVersion, c.EvidenceKeys) != nil {
			return nil, risk.ErrInvalidPolicy
		}
	}
	r.captcha = append([]risk.CaptchaEvidenceCustody(nil), c.CaptchaCustody...)
	if c.UseIssuer != nil {
		issuer := *c.UseIssuer
		if issuer.ValidateUseConfiguration(c.PolicyVersion, c.EvidenceKeys) != nil {
			return nil, risk.ErrInvalidPolicy
		}
		r.useIssuer = &issuer
	}
	if c.UseCounters != nil {
		state := c.UseCounters.state
		if r.useIssuer == nil || state == nil || state.schema != r.schema {
			return nil, risk.ErrInvalidPolicy
		}
		admission, err := state.config.Policy.Admit("identity.phone.password-reset-complete")
		if err != nil || admission.PolicyVersion != r.policy || admission.Profile.Window%time.Microsecond != 0 {
			return nil, risk.ErrInvalidPolicy
		}
		r.useCounters = state
	}
	if c.CommandCounters != nil {
		copy := *c.CommandCounters
		copy.Keys = append([]risk.CounterDigestKey(nil), copy.Keys...)
		p, err := risk.NewCommandCounterPolicy(copy)
		if err != nil {
			return nil, err
		}
		admission, err := copy.Policy.Admit("identity.profile.update")
		if err != nil || admission.PolicyVersion != c.PolicyVersion {
			return nil, risk.ErrInvalidPolicy
		}
		// Work persists fixed-window boundaries at PostgreSQL microsecond
		// precision. Reject unsupported intervals before any reservation can
		// truncate a duration or fail halfway through charging its dimensions.
		for _, action := range []risk.Action{"identity.password.change", "identity.admin.user-ban"} {
			protected, err := copy.Policy.Admit(action)
			if err != nil || protected.Profile.Window%time.Microsecond != 0 {
				return nil, risk.ErrInvalidPolicy
			}
		}
		r.counters, r.counterPolicy = &copy, p
	}
	if c.LockoutMutations != nil {
		if !c.EnforceLockouts || r.counters == nil {
			return nil, risk.ErrInvalidPolicy
		}
		state, err := newLockoutMutationState(*c.LockoutMutations, r.counterPolicy)
		if err != nil {
			return nil, err
		}
		r.lockoutMutation = state
	}
	return r, nil
}

// Descriptor identifies the native store, not current registration or authority.
func (*Repository) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}

// FeatureOperations returns owned issuance and explicitly selected lockout
// declarations. It does not grant caller authority or register global state.
func (r *Repository) FeatureOperations() []identity.FeatureOperation {
	operations := []identity.FeatureOperation{IssueOperation()}
	if r != nil && len(r.captcha) != 0 {
		operations = append(operations, CaptchaIssueOperation(identity.FeatureSubjectUser), CaptchaIssueOperation(identity.FeatureSubjectAnonymousFlow))
	}
	if r != nil && r.lockoutMutation != nil {
		operations = append(operations, LockoutOperation(risk.StartLockout), LockoutOperation(risk.EndLockout))
	}
	return operations
}

// ValidateFeatureCommand authenticates the complete signed core projection and
// checks exact protected audit/lifecycle declarations before reservation. It is
// pure, bounded and does not authorize the caller or establish commitment.
func (r *Repository) ValidateFeatureCommand(c identity.Command, p identitypostgres.CommandPlan) error {
	if r == nil || r.schema == "" {
		return risk.ErrInvalidEvidenceExecution
	}
	if s, ok := c.Feature(); ok && isCaptchaOperation(s.Operation) {
		return r.validateCaptchaFeature(c, p)
	}
	if s, ok := c.Feature(); ok && isLockoutOperation(s.Operation) {
		return r.validateLockoutFeature(c, p)
	}
	if _, err := restoreCommand(c, r.keys, r.policy); err != nil {
		return err
	}
	if p.SubjectType != "risk_evidence" || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != IssueOperation() || p.Capability != nil || p.Lifecycle == nil || !issueTransition(*p.Lifecycle) || len(p.Audits) != 1 {
		return risk.ErrInvalidEvidenceExecution
	}
	a := p.Audits[0]
	if a.EventType != "identity.risk.decide" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return risk.ErrInvalidEvidenceExecution
	}
	return nil
}

func issueTransition(l identitypostgres.LifecyclePlan) bool {
	return l.EventType == "risk.evidence_issued.v1" && l.BeforeVersion == 0 && l.AfterVersion == 1
}

// ApplyFeature runs only during this exact instance's active invocation. It
// materializes once at authoritative Work database time, preserving the original
// exclusive expiry, then inserts encrypted response custody and minimal scoped
// keyed linkage. The receipt is provisional and contains no bearer. Coordinator
// commit must persist the required audit, lifecycle and command result together;
// every error requires Abort. No private transaction or external callback runs.
func (r *Repository) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.schema == "" {
		return identity.FeatureReceipt{}, risk.ErrInvalidEvidenceExecution
	}
	if s, ok := c.Feature(); ok && isCaptchaOperation(s.Operation) {
		return r.applyCaptcha(ctx, w, c)
	}
	if s, ok := c.Feature(); ok && isLockoutOperation(s.Operation) {
		return r.applyLockout(ctx, w, c)
	}
	b, feature, transition, err := w.FeatureScope(r)
	s, ok := c.Feature()
	if err != nil || !ok || b != s.Binding || feature.Contributor != r.Descriptor() || feature.Operation != IssueOperation() || !issueTransition(transition) {
		return identity.FeatureReceipt{}, risk.ErrInvalidEvidenceExecution
	}
	issue, err := restoreCommand(c, r.keys, r.policy)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := issue.Materialize(now)
	if err != nil {
		return identity.FeatureReceipt{}, risk.ErrInvalidEvidenceExecution
	}
	envelope, err := r.cipher.seal(ctx, b, record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(envelope)
	digest := bindingDigest(b)
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return identity.FeatureReceipt{}, risk.ErrInvalidEvidenceExecution
	}
	p := issue.Prepared()
	n, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.issued_evidence(tenant_id,command_id,command_purpose,record_id,user_id,purpose,policy_version,key_version,binding_digest,intent_digest,proof_digest,evidence_digest,issued_at,expires_at,state,response_envelope) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,'issued',$15) ON CONFLICT DO NOTHING`, string(b.TenantID), id, b.OperationID, b.RecordID, string(b.UserID), string(p.Binding.Purpose), strconv.FormatUint(p.Binding.PolicyVersion, 10), int64(record.KeyVersion), digest[:], record.IntentDigest[:], record.ProofDigest[:], record.EvidenceDigest[:], record.IssuedAt, record.ExpiresAt, envelope)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: IssueOperation(), AfterVersion: 1}, nil
}

// RecoverParticipant supplies only this native participant's historical effect
// evidence under the coordinator's locked recovery invocation. An exact row is
// positive evidence, never a reconstructed successful receipt. Absence is
// negative only here: issuance is same-Work atomic and this profile never prunes
// rows. Corrupt or foreign linkage is unknown. Expiry is not rollback proof.
// For phone consumption, only exact reserved historical custody supplies
// noncommit evidence for this participant; every other participant must supply
// its own evidence before the coordinator grants terminal release authority.
func (r *Repository) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	unknown := func() (identitypostgres.RecoveryStatus, error) {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	if ctx == nil || r == nil || r.schema == "" {
		return unknown()
	}
	if b, e := w.CaptchaBinding(r); e == nil {
		status, err := r.recoverCaptchaUse(ctx, w, b)
		if err != nil || status != identitypostgres.RecoveryNotCommitted {
			return status, err
		}
		// One registered owner can cover multiple selected roles. A CAPTCHA
		// reservation is never negative proof for its counter or phone evidence.
		if counter, e := w.CommandCounterBinding(r); e == nil {
			status, err = r.recoverCommandCounter(ctx, w, counter)
			if err != nil || status != identitypostgres.RecoveryNotCommitted {
				return status, err
			}
		}
		if _, e := w.RiskBinding(r); e == nil {
			return r.recoverRiskEvidence(ctx, w)
		}
		return identitypostgres.RecoveryNotCommitted, nil
	}
	if b, e := w.CommandCounterBinding(r); e == nil {
		return r.recoverCommandCounter(ctx, w, b)
	}
	if scope, err := w.Scope(); err == nil && (scope.OperationID == "identity.phone.password-reset-request" || scope.OperationID == "identity.phone.password-reset-complete") {
		return r.recoverRiskEvidence(ctx, w)
	}
	b, feature, transition, err := w.FeatureScope(r)
	if err == nil && isCaptchaOperation(feature.Operation) {
		return r.recoverCaptcha(ctx, w, b, feature, transition)
	}
	if err == nil && isLockoutOperation(feature.Operation) {
		return r.recoverLockout(ctx, w, b, feature, transition)
	}
	if err != nil || feature.Contributor != r.Descriptor() || feature.Operation != IssueOperation() || !issueTransition(transition) {
		return unknown()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return unknown()
	}
	rows, err := w.Query(ctx, `SELECT record_id,user_id,command_purpose,binding_digest FROM `+r.schema+`.issued_evidence WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return unknown()
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return unknown()
		}
		return identitypostgres.RecoveryNotCommitted, nil
	}
	var recordID, userID, purpose string
	var stored []byte
	if rows.Scan(&recordID, &userID, &purpose, &stored) != nil || rows.Next() || rows.Err() != nil {
		return unknown()
	}
	digest := bindingDigest(b)
	if recordID != b.RecordID || userID != string(b.UserID) || purpose != b.OperationID || len(stored) != 32 || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return unknown()
	}
	return identitypostgres.RecoveryCommitted, nil
}
