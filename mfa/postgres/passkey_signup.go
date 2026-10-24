package mfapostgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// InitializePasskeySignup establishes known-empty factor authority only after
// the kernel actually creates this original prospective passkey-only account
// in the native signup Apply. It never infers absence from a missing row or
// resets an existing generation. Duplicate initialization fails, not upserts.
// Real WebAuthn verification, signup policy and session issuance remain with
// the native owner. Propagate every error to abort the sole borrowed Work.
func InitializePasskeySignup(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	user, err := w.PasskeyRegistrationUser(ctx, owner, command)
	if err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,1,0,$3,$4)`, string(user.TenantID), string(user.ID), id, b.OperationID)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequirePasskeySignupFactors locks the known-empty initial factor generation
// and its exact signup-command provenance during native Apply or final Check.
// The kernel must independently retain this Work's actual created user and
// credential reference. Missing/enrolled/changed/foreign state denies; it never
// selects a newer generation or supplies authentication/recovery permission.
// The returned projection is provisional, not a cacheable validity lease.
// Return every error to the coordinator so all account/session effects abort.
func RequirePasskeySignupFactors(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command) (mfa.FactorAuthority, error) {
	u, err := w.PasskeyRegistrationUser(ctx, owner, command)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	b, err := w.Scope()
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND initialized_command_id=$3 AND initialized_purpose=$4 FOR UPDATE`, string(u.TenantID), string(u.ID), id, b.OperationID)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return mfa.FactorAuthority{}, identity.UnavailableError{}
		}
		return mfa.FactorAuthority{}, identity.ForbiddenError{}
	}
	var version string
	var active int32
	if rows.Scan(&version, &active) != nil || rows.Next() || rows.Err() != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || v != 1 || version != "1" || active != 0 {
		return mfa.FactorAuthority{}, identity.ForbiddenError{}
	}
	return mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: u.TenantID, UserID: u.ID, Version: 1, ActiveFactors: 0})
}
