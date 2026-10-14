package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// MFARecoverySessionEffect owns all-subject session revocation for exact native
// recovery regeneration Work. It owns no pool, transaction, cache or goroutine.
// The native MFA owner must have authenticated the source and consumed its fresh
// factor proof in this same Work before Apply. This never grants continuing
// access to a deliberately revoked source or issues replacement credentials.
type MFARecoverySessionEffect struct {
	config           Config
	profile          IdentifierAdmissionConfig
	schema           string
	factorManagement bool
	disable          bool
	replacement      bool
}

// NewMFARecoverySessionEffect freezes native password/password-MFA ownership
// without IO. The whole-set cap is1024 active sessions; excess denies and rolls
// back every effect. Install MFARecoverySessionMigrationSource before use.
func NewMFARecoverySessionEffect(c Config, p IdentifierAdmissionConfig) (*MFARecoverySessionEffect, error) {
	guard, err := NewPasswordMFAActionSessionGuard(c, p)
	if err != nil {
		return nil, err
	}
	return &MFARecoverySessionEffect{config: guard.config, profile: guard.profile, schema: pgx.Identifier{c.Schema}.Sanitize()}, nil
}

// NewMFAFactorUpdateSessionEffect selects the same native session disposition
// owner for exact factor-update Work instead of recovery regeneration. It does
// not select regeneration, accept an arbitrary action or grant continuing
// session authority. Install MFAFactorUpdateSessionMigrationSource after the
// existing disposition history. All inherited caps and rollback rules apply.
func NewMFAFactorUpdateSessionEffect(c Config, p IdentifierAdmissionConfig) (*MFARecoverySessionEffect, error) {
	e, err := NewMFARecoverySessionEffect(c, p)
	if err != nil {
		return nil, err
	}
	e.factorManagement = true
	return e, nil
}

// NewMFADisableSessionEffect selects exact disable-purpose disposition ownership.
// It does not accept update, regeneration or administrator-reset scope. Install
// MFADisableSessionMigrationSource after the existing disposition prefix.
func NewMFADisableSessionEffect(c Config, p IdentifierAdmissionConfig) (*MFARecoverySessionEffect, error) {
	e, err := NewMFARecoverySessionEffect(c, p)
	if err != nil {
		return nil, err
	}
	e.disable = true
	return e, nil
}

// NewMFATOTPReplacementSessionEffect selects session revocation only for
// code-confirmed successor activation. URI and pending initiation cannot use
// this disposition. Install MFATOTPReplacementSessionMigrationSource first.
func NewMFATOTPReplacementSessionEffect(c Config, p IdentifierAdmissionConfig) (*MFARecoverySessionEffect, error) {
	e, err := NewMFARecoverySessionEffect(c, p)
	if err != nil {
		return nil, err
	}
	e.replacement = true
	return e, nil
}

func (e *MFARecoverySessionEffect) acceptsScope(b identity.CommandBinding, f kernel.FeatureRegistration, l kernel.LifecyclePlan) bool {
	if e == nil {
		return false
	}
	if e.replacement {
		_, err := identity.ParseCommandID(b.RecordID)
		return err == nil && b.RecordID != string(b.UserID) && b.SchemaVersion == 1 && b.OperationID == "identity.mfa.totp-verify" && b.SchemaID == "mfa-totp-enrollment-confirm" && f.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) && l.EventType == "factor.enrolled.v1" && l.BeforeVersion > 0 && l.BeforeVersion < math.MaxUint64 && l.AfterVersion == l.BeforeVersion+1
	}
	if e.disable {
		return b.SchemaVersion == 1 && b.OperationID == "identity.mfa.disable" && b.SchemaID == "mfa-disable" && b.RecordID == string(b.UserID) && f.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) && l.EventType == "factor.removed.v1" && l.BeforeVersion > 0 && l.BeforeVersion < math.MaxUint64 && l.AfterVersion == l.BeforeVersion+1
	}
	if !e.factorManagement {
		return mfaRecoveryEffectScope(b, f, l)
	}
	return b.SchemaVersion == 1 && b.OperationID == "identity.mfa.factor-update" && b.SchemaID == "mfa-factor-update" && b.RecordID == string(b.UserID) && f.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) && (l.EventType == "factor.updated.v1" || l.EventType == "factor.removed.v1") && l.BeforeVersion > 0 && l.BeforeVersion < math.MaxUint64 && l.AfterVersion == l.BeforeVersion+1
}

func mfaRecoveryEffectScope(b identity.CommandBinding, f kernel.FeatureRegistration, l kernel.LifecyclePlan) bool {
	return nativeMFAActionBinding(b) && b.OperationID == "identity.mfa.recovery-regenerate" && b.RecordID == string(b.UserID) && f.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: "mfa-recovery-regenerate", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) && l.EventType == "factor.recovery-regenerated.v1" && l.BeforeVersion > 0 && l.BeforeVersion < math.MaxUint64 && l.AfterVersion == l.BeforeVersion+1
}

func (e *MFARecoverySessionEffect) original(c identity.Command, b identity.CommandBinding) (session.Session, [32]byte, error) {
	zero := [32]byte{}
	spec, ok := c.Feature()
	if !ok || spec.Binding != b {
		return session.Session{}, zero, session.ErrInvalidSessionCommand
	}
	fields := make([]identity.FeatureField, 0, len(spec.Fields))
	for _, field := range spec.Fields {
		if strings.HasPrefix(field.Name, originalSessionPrefix) {
			fields = append(fields, field)
		}
	}
	original, err := OriginalSessionFromFields(b.TenantID, b.UserID, fields)
	if err != nil {
		return session.Session{}, zero, err
	}
	wire, _, err := encodeRecord(original)
	if err != nil {
		return session.Session{}, zero, err
	}
	return original, sha256.Sum256(wire), nil
}
func mfaRecoveryEffectBinding(c identity.Command, l kernel.LifecyclePlan) ([32]byte, error) {
	spec, ok := c.Feature()
	if !ok {
		return [32]byte{}, session.ErrInvalidSessionCommand
	}
	wire, err := json.Marshal(struct {
		Profile string
		Spec    identity.FeatureCommandSpec
		Life    kernel.LifecyclePlan
	}{"mfa-recovery-session-effect-v1", spec, l})
	if err != nil {
		return [32]byte{}, session.ErrInvalidSessionCommand
	}
	defer clear(wire)
	return sha256.Sum256(wire), nil
}
func mfaRecoveryEffectResult(binding, source, chain [32]byte, count uint32, before, after uint64) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("mfa-recovery-session-result-v1\x00"))
	_, _ = h.Write(binding[:])
	_, _ = h.Write(source[:])
	_, _ = h.Write(chain[:])
	var numbers [20]byte
	binary.BigEndian.PutUint32(numbers[:4], count)
	binary.BigEndian.PutUint64(numbers[4:12], before)
	binary.BigEndian.PutUint64(numbers[12:], after)
	_, _ = h.Write(numbers[:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func (e *MFARecoverySessionEffect) requirePrimary(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, original session.Session, b identity.CommandBinding) error {
	guard := PasswordMFAActionSessionGuard{config: e.config, profile: e.profile}
	a, err := guard.admission(original, b)
	if err != nil || a.credential == nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, a.directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, owner, *a.credential); err != nil {
		return err
	}
	return w.RequireActiveUserAuthorization(ctx, owner, a.policy)
}

// Apply revokes every active subject session in stable bounded pages and
// persists original effect evidence atomically. MFA owns the factor-generation
// successor and proof use; this module alone writes its sessions. The existing
// coordinator tenant mutex precedes source/share and whole-set/write fences.
// Every error must abort all pending proof, recovery, session and event changes.
func (e *MFARecoverySessionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || e == nil {
		return session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || !e.acceptsScope(b, f, l) {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	original, source, err := e.original(c, b)
	if err != nil {
		return err
	}
	if err := e.requirePrimary(bounded, w, owner, original, b); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, original); err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil {
		return err
	}
	binding, err := mfaRecoveryEffectBinding(c, l)
	if err != nil {
		return err
	}
	cursor, count, chain := "", uint32(0), resetSessionChain()
	found := false
	for {
		rows, err := w.Query(bounded, `SELECT session_id,version::text FROM `+e.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active' AND session_id>$3 ORDER BY session_id LIMIT 16 FOR UPDATE`, string(b.TenantID), string(b.UserID), cursor)
		if err != nil {
			return err
		}
		type selected struct {
			id, version string
			value       uint64
		}
		page := make([]selected, 0, 16)
		for rows.Next() {
			var row selected
			if err = rows.Scan(&row.id, &row.version); err != nil {
				break
			}
			row.value, err = canonicalPasswordVersion(row.version)
			if err != nil || !scopeID(row.id) || row.id <= cursor || len(page) == 16 {
				err = ErrInvalidRecord
				break
			}
			cursor = row.id
			page = append(page, row)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if uint64(count)+uint64(len(page)) > 1024 {
			return identity.ConflictError{}
		}
		for _, row := range page {
			n, err := w.Exec(bounded, `UPDATE `+e.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active'`, string(b.TenantID), string(b.UserID), row.id, row.version)
			if err != nil {
				return err
			}
			if n != 1 {
				return identity.ConflictError{}
			}
			if row.id == s.SessionID {
				if row.value != s.Version {
					return identity.ForbiddenError{}
				}
				found = true
			}
			count++
			chain = resetSessionNext(chain, row.id, row.value)
		}
		if len(page) < 16 {
			break
		}
	}
	if !found || count == 0 {
		return identity.ForbiddenError{}
	}
	result := mfaRecoveryEffectResult(binding, source, chain, count, l.BeforeVersion, l.AfterVersion)
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	n, err := w.Exec(bounded, `INSERT INTO `+e.schema+`.mfa_recovery_dispositions(tenant_id,command_id,purpose,user_id,source_session_id,source_session_version,source_digest,before_factor_version,after_factor_version,revoked_count,effects_digest,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8::numeric,$9::numeric,$10,$11,$12,$13)`, string(b.TenantID), id, b.OperationID, string(b.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), source[:], strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10), int64(count), chain[:], binding[:], result[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Check validates this command's deliberate source revocation, retained whole-
// set evidence and still-current primary directory/credential/policy fences.
// The native MFA owner independently checks its exact factor successor and
// consumed proof. This is commit eligibility, never ongoing authentication.
func (e *MFARecoverySessionEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || e == nil {
		return session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || !e.acceptsScope(b, f, l) {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	original, source, err := e.original(c, b)
	if err != nil {
		return err
	}
	if err := e.requirePrimary(bounded, w, owner, original, b); err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil {
		return err
	}
	binding, err := mfaRecoveryEffectBinding(c, l)
	if err != nil {
		return err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(bounded, `SELECT d.source_digest,d.revoked_count,d.effects_digest,d.binding_digest,d.result_digest,s.record::text,NOT EXISTS(SELECT 1 FROM `+e.schema+`.sessions a WHERE a.tenant_id=d.tenant_id AND a.user_id=d.user_id AND a.state='active') FROM `+e.schema+`.mfa_recovery_dispositions d JOIN `+e.schema+`.sessions s ON s.tenant_id=d.tenant_id AND s.user_id=d.user_id AND s.session_id=d.source_session_id AND s.version=d.source_session_version AND s.state='revoked' WHERE d.tenant_id=$1 AND d.user_id=$2 AND d.command_id=$3 AND d.purpose=$4 AND d.source_session_id=$5 AND d.source_session_version=$6::numeric AND d.before_factor_version=$7::numeric AND d.after_factor_version=$8::numeric`, string(b.TenantID), string(b.UserID), id, b.OperationID, s.SessionID, strconv.FormatUint(s.Version, 10), strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10))
	if err != nil {
		return err
	}
	var sourceRaw, chainRaw, bindingRaw, resultRaw, record []byte
	var count int64
	var noActive bool
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&sourceRaw, &count, &chainRaw, &bindingRaw, &resultRaw, &record, &noActive)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	defer clear(record)
	want, _, encodeErr := encodeRecord(original)
	if err != nil || extra || rowErr != nil || encodeErr != nil || count < 1 || count > 1024 || len(sourceRaw) != 32 || len(chainRaw) != 32 || len(bindingRaw) != 32 || len(resultRaw) != 32 {
		return identity.UnavailableError{}
	}
	// JSONB text is not the original byte spelling; decode through this owner's
	// canonical record codec before comparing the complete immutable projection.
	decoded, decodeErr := decodeRecord(record)
	if decodeErr != nil {
		return identity.UnavailableError{}
	}
	actual, _, decodeErr := encodeRecord(decoded)
	if decodeErr != nil || !bytes.Equal(actual, want) || !noActive || !bytes.Equal(sourceRaw, source[:]) || !bytes.Equal(bindingRaw, binding[:]) {
		return identity.ForbiddenError{}
	}
	result := mfaRecoveryEffectResult(binding, source, [32]byte(chainRaw), uint32(count), l.BeforeVersion, l.AfterVersion)
	if !bytes.Equal(resultRaw, result[:]) {
		return identity.UnavailableError{}
	}
	return bounded.Err()
}

// Recover reads retained original disposition evidence, not today's mutable
// sessions or a newly inferred revocation. It cannot revoke, authenticate or
// disclose credentials; every native participant must agree before recovery.
func (e *MFARecoverySessionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || !e.acceptsScope(b, f, l) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(bounded, `SELECT source_session_id,source_session_version::text,source_digest,revoked_count,effects_digest,binding_digest,result_digest,before_factor_version::text,after_factor_version::text FROM `+e.schema+`.mfa_recovery_dispositions WHERE tenant_id=$1 AND user_id=$2 AND command_id=$3 AND purpose=$4`, string(b.TenantID), string(b.UserID), id, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var sourceID, sourceVersion, before, after string
	var source, chain, binding, result []byte
	var count int64
	if rows.Scan(&sourceID, &sourceVersion, &source, &count, &chain, &binding, &result, &before, &after) != nil || rows.Next() || rows.Err() != nil || !scopeID(sourceID) || count < 1 || count > 1024 || len(source) != 32 || len(chain) != 32 || len(binding) != 32 || len(result) != 32 || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if _, err := canonicalPasswordVersion(sourceVersion); err != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	want := mfaRecoveryEffectResult([32]byte(binding), [32]byte(source), [32]byte(chain), uint32(count), l.BeforeVersion, l.AfterVersion)
	if !bytes.Equal(result, want[:]) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

// Format redacts profile and schema configuration.
func (*MFARecoverySessionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFARecoverySessionEffect(redacted)"))
}

// MarshalJSON rejects implicit native configuration export.
func (*MFARecoverySessionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit native configuration export.
func (*MFARecoverySessionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

var _ mfapg.RecoveryRegenerationSessionEffects = (*MFARecoverySessionEffect)(nil)
