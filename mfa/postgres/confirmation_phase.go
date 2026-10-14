package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
	envelope "github.com/faustbrian/go-secret-envelope"
)

func (p *totpURIPhase) admitConfirmation(ctx context.Context, w kernel.Work) error {
	m := p.pending.metadata()
	b := p.pending.binding()
	authority, err := readFactorAuthority(ctx, w, b, b.UserID, p.pending.AuthorityVersion)
	if err != nil {
		return err
	}
	if p.pending.Replacement != nil {
		if err = p.checkReplacementPredecessor(ctx, w); err != nil {
			return err
		}
	} else {
		if err = authority.RequireEmailRecovery(b.TenantID, b.UserID); err != nil {
			return err
		}
	}
	var row string
	var wire, parent []byte
	var expires time.Time
	err = completionTOTPStore(w).query(ctx, `SELECT row_version::text,encrypted_secret,created_command_id,enrollment_expires_at FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND activation_command_id IS NULL FOR UPDATE`, []any{string(b.TenantID), string(b.UserID), m.FactorID}, &row, &wire, &parent, &expires)
	defer clear(wire)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if row != strconv.FormatUint(p.pending.RowVersion, 10) || sha256.Sum256(wire) != sha256.Sum256(p.pending.Wire) || base64.RawURLEncoding.EncodeToString(parent) != string(b.CommandID) || !expires.Equal(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(m.CreatedAt) || !now.Before(expires) {
		return identity.ForbiddenError{}
	}
	return p.primary.Check(ctx, w, p, p.command)
}

func (p *totpURIPhase) restoreConfirmationSecret(ctx context.Context) error {
	p.secret.Destroy()
	m := p.pending.metadata()
	binding, err := totpEncryptionContext(m.TenantID, m.UserID, m.FactorID, 1, m.Profile)
	if err != nil {
		return err
	}
	sealed, err := envelope.ParseEnvelope(p.pending.Wire)
	if err != nil {
		return identity.UnavailableError{}
	}
	raw, err := p.state.enrollment.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	if err != nil {
		return enrollmentReadError(ctx)
	}
	defer clear(raw)
	if len(raw) != 32 {
		return identity.UnavailableError{}
	}
	p.secret, err = primitive.NewSecret(raw)
	return err
}

func (p *totpURIPhase) applyConfirmation(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	err := activatePendingTOTPProfile(ctx, w, p, c, p.pending.metadata(), p.pending.RowVersion, p.pending.AuthorityVersion, p.pending.Wire, p.secret, p.confirmRequest.Code, p.confirmation.verifier, p.confirmation.keyVersion, p.pending.Replacement, p.predecessorRowVersion)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.pending.Replacement != nil {
		p.activated = true
		if err := p.state.config.Replacement.Sessions.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err = p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: confirmationOperation(), BeforeVersion: p.pending.RowVersion, AfterVersion: p.pending.RowVersion + 1}, nil
}

func (p *totpURIPhase) recoverConfirmation(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() || f.Operation != confirmationOperation() || life.EventType != "factor.enrolled.v1" || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT f.user_id,f.factor_id,f.activation_before_version::text,r.state,r.row_version::text,f.created_purpose FROM identity_mfa.totp_factors f LEFT JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.user_id=f.user_id AND r.factor_id=f.factor_id AND r.set_id=f.factor_id WHERE f.tenant_id=$1 AND f.activation_command_id=$2`, string(b.TenantID), id)
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
	var user, factor, before, purpose string
	var state *int16
	var recoveryVersion *string
	if rows.Scan(&user, &factor, &before, &state, &recoveryVersion, &purpose) != nil || rows.Next() || rows.Err() != nil || user != string(b.UserID) || factor != b.RecordID || before != strconv.FormatUint(life.BeforeVersion, 10) || state == nil || *state < 2 || recoveryVersion == nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(*recoveryVersion, 10, 64)
	if err != nil || v < 2 {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	rows.Close()
	if purpose == factorUpdateOperation().OperationID {
		if p.state.config.Replacement == nil || nilEnrollmentPrimary(p.state.config.Replacement.Sessions) {
			return kernel.RecoveryUnknown, identity.ForbiddenError{}
		}
		return p.state.config.Replacement.Sessions.Recover(ctx, w, p)
	}
	if purpose != enrollmentOperation().OperationID {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return kernel.RecoveryCommitted, nil
}
