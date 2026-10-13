package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

func (p *factorUpdatePhase) validReplacementInput(in *factorUpdateInput) bool {
	if p.request.Action != mfa.Replace {
		return in.Replacement == nil && in.ReplacementOrigin == "" && in.ReplacementNetwork == "" && in.ReplacementUntil == nil
	}
	if p.state.config.Replacement == nil || in.Replacement == nil || in.ReplacementUntil == nil || !in.CreatedAt.Before(*in.ReplacementUntil) || in.ReplacementUntil.After(in.Replacement.ExpiresAt) || in.Before.ID != mfa.FactorID(in.Record.Original.CredentialID) {
		return false
	}
	m := in.Replacement
	id, err := identity.ParseCommandID(m.FactorID)
	return err == nil && id != in.Binding.CommandID && m.FactorID != string(in.Before.ID) && m.TenantID == in.Binding.TenantID && m.UserID == in.Binding.UserID && m.AuthorityVersion == in.Record.FactorAuthorityVersion && m.Profile == p.state.shared.config.Profile && m.CreatedAt.Equal(in.CreatedAt) && m.ExpiresAt.Equal(m.CreatedAt.Add(p.state.shared.config.TTL)) && in.ReplacementOrigin == p.request.Origin && in.ReplacementNetwork == p.request.Network
}

func (p *factorUpdatePhase) restoreReplacementMaterial(ctx context.Context, generation uint64, out *totpEnrollmentOutput) error {
	if out == nil || p.input.Replacement == nil || out.Schema != 1 || out.Generation != generation || out.RecoveryKeyVersion != p.state.shared.config.RecoveryKeyVersion || !reflect.DeepEqual(out.Meta, *p.input.Replacement) || len(out.Codes) != int(p.state.config.Replacement.RecoveryCodes) || len(out.Digests) != len(out.Codes) || len(out.Envelope) == 0 || len(out.Envelope) > 4096 {
		return invalidAuthority()
	}
	binding, err := totpEncryptionContext(out.Meta.TenantID, out.Meta.UserID, out.Meta.FactorID, 1, out.Meta.Profile)
	if err != nil {
		return err
	}
	sealed, err := envelope.ParseEnvelope(out.Envelope)
	if err != nil {
		return invalidAuthority()
	}
	secret, err := p.state.shared.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	valid := err == nil && len(secret) == 32
	clear(secret)
	if !valid {
		return identity.UnavailableError{}
	}
	key := p.state.shared.config.recoveryKey()
	defer clear(key[:])
	codeBinding, err := enrollmentRecoveryBinding(out.Meta)
	if err != nil {
		return err
	}
	defer clear(codeBinding)
	seen := make(map[[32]byte]bool, len(out.Codes))
	for i, raw := range out.Codes {
		if len(raw) != 22 {
			return invalidAuthority()
		}
		code, err := auth.NewRecoveryCode(string(raw))
		if err != nil {
			return invalidAuthority()
		}
		digest, err := code.KeyedDigest(key, codeBinding)
		if err != nil || digest != out.Digests[i] || seen[digest] {
			return identity.ForbiddenError{}
		}
		seen[digest] = true
	}
	if p.replacement != nil {
		clearEnrollmentOutput(p.replacement)
	}
	p.replacement = out
	return nil
}

// Initiation changes only predecessor metadata and adds an unconfirmed child.
// Its factor authority and source session stay unchanged until confirmation.
// Existing tenant serialization and original proof lock own the whole effect;
// generation, encryption and recovery digests were restored before these locks.
func (p *factorUpdatePhase) applyReplacement(ctx context.Context, w kernel.Work, c identity.Command, now time.Time) (identity.FeatureReceipt, error) {
	if p.replacement == nil || p.input.Replacement == nil || now.Before(p.input.CreatedAt) || !now.Before(p.input.Replacement.ExpiresAt) {
		return identity.FeatureReceipt{}, invalidAuthority()
	}
	b, r, m := p.input.Binding, p.request, *p.input.Replacement
	rows, err := w.Query(ctx, `SELECT a.active_factors,t.row_version::text,t.label,(SELECT count(*) FROM identity_mfa.totp_factors q WHERE q.tenant_id=t.tenant_id AND q.user_id=t.user_id AND q.state=1 AND q.enrollment_expires_at>$4) FROM identity_mfa.totp_factors t JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2 AND t.confirmed_at IS NOT NULL FOR UPDATE OF t`, string(b.TenantID), string(b.UserID), string(r.FactorID), now)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var active int32
	var pending int64
	var version, label string
	if !rows.Next() {
		rows.Close()
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	err = rows.Scan(&active, &version, &label, &pending)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if active != 1 || pending < 0 || pending >= 8 || version != strconv.FormatUint(r.ExpectedVersion, 10) || label != p.input.Before.Label {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	// Expired pending replacement custody cannot block a fresh ceremony forever.
	// It is retired only under the same admitted predecessor scope and Work.
	if _, err := w.Exec(ctx, `UPDATE identity_mfa.recovery_sets s SET state=3,row_version=s.row_version+1 FROM identity_mfa.totp_factors t WHERE s.tenant_id=t.tenant_id AND s.user_id=t.user_id AND s.factor_id=t.factor_id AND t.tenant_id=$1 AND t.user_id=$2 AND t.replaces_factor_id=$3 AND t.state=1 AND t.enrollment_expires_at<=$4 AND s.state<>3`, string(b.TenantID), string(b.UserID), string(r.FactorID), now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL,label='',row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND replaces_factor_id=$3 AND state=1 AND enrollment_expires_at<=$4`, string(b.TenantID), string(b.UserID), string(r.FactorID), now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$4::numeric`, string(b.TenantID), string(b.UserID), string(r.FactorID), version)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, replacementWriteError(err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	n, err = w.Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,replaces_factor_id,replaces_version) VALUES($1,$2,$3,1,1,1,$4,$5,$6,$7,$8,$9,$10,'identity.mfa.factor-update',$11,$12,$13,$14::numeric)`, string(b.TenantID), string(b.UserID), m.FactorID, m.Profile.Algorithm, int16(m.Profile.Digits), int16(m.Profile.Period/time.Second), int16(m.Profile.AllowedSkewSteps), m.Profile.Issuer, p.replacement.Envelope, id, m.CreatedAt, m.ExpiresAt, string(r.FactorID), strconv.FormatUint(r.ExpectedVersion+1, 10))
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, replacementWriteError(err)
	}
	n, err = w.Exec(ctx, `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at) VALUES($1,$2,$3,$3,1,1,1,$4,$5,$6,'identity.mfa.factor-update',$7)`, string(b.TenantID), string(b.UserID), m.FactorID, len(p.replacement.Digests), int64(p.replacement.RecoveryKeyVersion), id, m.CreatedAt)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, replacementWriteError(err)
	}
	for index, digest := range p.replacement.Digests {
		n, err := w.Exec(ctx, `INSERT INTO identity_mfa.recovery_codes(tenant_id,set_id,code_index,digest) VALUES($1,$2,$3,$4)`, string(b.TenantID), m.FactorID, index, digest[:])
		if err != nil || n != 1 {
			return identity.FeatureReceipt{}, replacementWriteError(err)
		}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_verifications SET used_command_id=$4,used_purpose=$5,used_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND used_command_id IS NULL AND used_purpose IS NULL AND used_at IS NULL`, string(b.TenantID), string(b.UserID), string(p.input.Record.Original.Proof.Proof.ID), id, b.OperationID, now)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, replacementWriteError(err)
	}
	authority := strconv.FormatUint(m.AuthorityVersion, 10)
	n, err = w.Exec(ctx, `INSERT INTO identity_mfa.factor_update_effects(tenant_id,user_id,command_id,purpose,factor_id,before_version,after_version,before_authority,after_authority,proof_id,action,replacement_factor_id) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$8::numeric,$9,3,$10)`, string(b.TenantID), string(b.UserID), id, b.OperationID, string(r.FactorID), version, strconv.FormatUint(r.ExpectedVersion+1, 10), authority, string(p.input.Record.Original.Proof.Proof.ID), m.FactorID)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, replacementWriteError(err)
	}
	if err := p.checkReplacement(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.result = mfa.FactorProjection{ID: mfa.FactorID(m.FactorID), Method: "totp", State: mfa.FactorPending, CreatedAt: m.CreatedAt, Version: 1}
	p.applied = true
	l := p.lifecycle()
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

func replacementWriteError(err error) error {
	if err != nil {
		return err
	}
	return identity.ConflictError{}
}

func (p *factorUpdatePhase) checkReplacement(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.lockProof(ctx, w, true); err != nil {
		return err
	}
	b, m := p.input.Binding, p.input.Replacement
	if m == nil || p.replacement == nil {
		return invalidAuthority()
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if err := RequireTOTPSessionFactor(ctx, w, p, b.UserID, p.input.Record.Original.CredentialID, TOTPSessionFactorState{EnrollmentVersion: p.input.Record.Original.CredentialVersion, AuthorityVersion: m.AuthorityVersion}); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT a.active_factors,p.row_version::text,p.label,p.encrypted_secret IS NOT NULL AND p.last_step IS NOT NULL,n.encrypted_secret,n.enrollment_expires_at,s.code_count,(SELECT count(*) FROM identity_mfa.recovery_codes q WHERE q.tenant_id=s.tenant_id AND q.set_id=s.set_id AND q.consumed_at IS NULL) FROM identity_mfa.totp_factors p JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) JOIN identity_mfa.totp_factors n ON n.tenant_id=p.tenant_id AND n.user_id=p.user_id AND n.replaces_factor_id=p.factor_id JOIN identity_mfa.recovery_sets s ON s.tenant_id=n.tenant_id AND s.user_id=n.user_id AND s.factor_id=n.factor_id WHERE p.tenant_id=$1 AND p.user_id=$2 AND p.factor_id=$3 AND p.state=2 AND n.factor_id=$4 AND n.state=1 AND n.row_version=1 AND n.replaces_version=p.row_version AND s.set_id=n.factor_id AND s.state=1 AND s.row_version=1 AND n.created_command_id=s.created_command_id AND n.created_purpose='identity.mfa.factor-update' AND s.created_purpose=n.created_purpose`, string(b.TenantID), string(b.UserID), string(p.targetID()), m.FactorID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var active int32
	var count int16
	var unused int64
	var version, label string
	var intact bool
	var wire []byte
	var expires time.Time
	if !rows.Next() || rows.Scan(&active, &version, &label, &intact, &wire, &expires, &count, &unused) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if active != 1 || version != strconv.FormatUint(p.targetVersion()+1, 10) || label != p.input.Before.Label || !intact || !expires.Equal(m.ExpiresAt) || sha256.Sum256(wire) != sha256.Sum256(p.replacement.Envelope) || int(count) != len(p.replacement.Digests) || unused != int64(count) {
		return identity.ForbiddenError{}
	}
	rows.Close()
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.input.Until) || !now.Before(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.risk.CheckAt(ctx, now)
}

func (p *factorUpdatePhase) replacementDelivery(ctx context.Context) (*mfa.TOTPReplacementEnrollment, error) {
	if ctx == nil || ctx.Err() != nil || !p.applied || p.replacement == nil || !time.Now().Before(p.input.Until) {
		return nil, identity.ForbiddenError{}
	}
	m := p.replacement.Meta
	codes, err := enrollmentRecoveryDelivery(ctx, p.replacement.Codes)
	if err != nil {
		return nil, err
	}
	return &mfa.TOTPReplacementEnrollment{Enrollment: mfa.Enrollment{ID: mfa.EnrollmentID(m.FactorID), FactorMethod: "totp", ExpiresAt: m.ExpiresAt, Version: 1}, RecoveryMaterial: codes}, nil
}

// Historical initiation recovery authenticates committed lineage and proof use,
// not today's predecessor state or source-session eligibility. The source was
// deliberately preserved at initiation: absence of a revoke-all session effect
// is expected, not evidence of rollback. Later confirmation/retirement keeps
// this creation attribution and never authorizes a second secret delivery.
func (p *factorUpdatePhase) recoverReplacement(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding, l kernel.LifecyclePlan) (bool, kernel.RecoveryStatus, error) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return false, kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT e.action,e.before_version::text,e.after_version::text,e.before_authority::text,e.after_authority::text,v.used_purpose,n.factor_id,n.replaces_factor_id,n.replaces_version::text,s.code_count,(SELECT count(*) FROM identity_mfa.recovery_codes q WHERE q.tenant_id=s.tenant_id AND q.set_id=s.set_id) FROM identity_mfa.factor_update_effects e LEFT JOIN identity_mfa.factor_verifications v ON v.tenant_id=e.tenant_id AND v.user_id=e.user_id AND v.proof_id=e.proof_id AND v.used_command_id=e.command_id LEFT JOIN identity_mfa.totp_factors n ON n.tenant_id=e.tenant_id AND n.user_id=e.user_id AND n.factor_id=e.replacement_factor_id AND n.created_command_id=e.command_id AND n.created_purpose=e.purpose LEFT JOIN identity_mfa.recovery_sets s ON s.tenant_id=n.tenant_id AND s.user_id=n.user_id AND s.factor_id=n.factor_id AND s.set_id=n.factor_id AND s.created_command_id=e.command_id AND s.created_purpose=e.purpose WHERE e.tenant_id=$1 AND e.user_id=$2 AND e.command_id=$3 AND e.purpose='identity.mfa.factor-update'`, string(b.TenantID), string(b.UserID), id)
	if err != nil {
		return false, kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		return false, kernel.RecoveryUnknown, rows.Err()
	}
	var action int16
	var before, after, beforeAuthority, afterAuthority string
	var purpose, factor, predecessor, version *string
	var count *int16
	var actual int64
	if rows.Scan(&action, &before, &after, &beforeAuthority, &afterAuthority, &purpose, &factor, &predecessor, &version, &count, &actual) != nil || rows.Next() || rows.Err() != nil {
		return false, kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if action != int16(mfa.Replace) {
		return false, kernel.RecoveryUnknown, nil
	}
	v, parseErr := strconv.ParseUint(beforeAuthority, 10, 64)
	if l.EventType != "factor.updated.v1" || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || beforeAuthority != afterAuthority || parseErr != nil || v == 0 || v == ^uint64(0) || beforeAuthority != strconv.FormatUint(v, 10) || purpose == nil || *purpose != b.OperationID || factor == nil || predecessor == nil || *factor == *predecessor || version == nil || *version != after || count == nil || *count < 1 || *count > 64 || actual != int64(*count) {
		return true, kernel.RecoveryUnknown, nil
	}
	return true, kernel.RecoveryCommitted, nil
}
