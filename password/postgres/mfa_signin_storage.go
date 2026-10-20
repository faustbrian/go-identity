package passwordpostgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Only the actual comparison-owning challenge phase may persist this record.
// It is immutable domain evidence and must share the original coordinator
// transaction with browser consumption, continuation, child and required effects.
// No final signin source, session, transaction or proof authority is created here.
func persistMFASigninPrimary(ctx context.Context, w kernel.Work, owner kernel.PasswordMFAChallengeContributor, command identity.Command, r mfaSigninPrimary, keys map[string]ed25519.PublicKey, continuation mfa.PartialAuthContinuation) error {
	if ctx == nil || owner == nil {
		return password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	challenge, err := w.PasswordMFAChallenge(owner)
	if err != nil {
		return err
	}
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	profile := mfaSigninPrimaryProfile
	if b.OperationID == "identity.username.signin" {
		profile = usernameMFASigninPrimaryProfile
	} else if b.OperationID == "identity.phone.password-signin" {
		profile = phoneMFASigninPrimaryProfile
	} else if b.OperationID != "identity.password.signin" {
		return password.ErrPasswordWork
	}
	if r.Profile != profile {
		return identity.ForbiddenError{}
	}
	c, err := continuation.Bindings()
	if err != nil {
		return password.ErrPasswordWork
	}
	scope, err := continuation.ScopeDigest()
	if err != nil {
		return err
	}
	wire, digest, err := encodeMFASigninPrimary(r)
	if err != nil {
		return err
	}
	defer clear(wire)
	if _, _, err := decodeMFASigninPrimary(wire, keys, r.Issuer, r.Environment, r.Proof.ID, string(b.TenantID), string(challenge.UserID)); err != nil {
		return err
	}
	if string(r.Proof.ID) != string(b.CommandID) || c.PrimaryProofID != r.Proof.ID || c.PrimaryProofDigest != digest || !c.PrimaryProofExpiresAt.Equal(r.Proof.ExpiresAt) || c.TenantID != b.TenantID || c.SubjectID != identity.SubjectID(challenge.UserID) || string(c.SourcePreAuthID) != b.AnonymousFlowID || string(c.ID) != string(challenge.ID) || scope != challenge.ScopeDigest || c.FactorVersion != challenge.FactorVersion || c.PolicyVersion != challenge.PolicyVersion || !c.IssuedAt.Equal(challenge.IssuedAt) || !c.ExpiresAt.Equal(challenge.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := continuation.RequirePending(now); err != nil {
		return err
	}
	if now.Before(r.Proof.IssuedAt) || !now.Before(r.Proof.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	commandID, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(commandID) != 16 {
		return password.ErrPasswordWork
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_password.mfa_primary_records(proof_id,tenant_id,user_id,command_id,purpose,record_digest,record) VALUES($1,$2,$3,$4,$5,$6,$7)`, string(r.Proof.ID), string(b.TenantID), string(challenge.UserID), commandID, b.OperationID, digest[:], wire)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return mfapg.PersistPasswordContinuation(ctx, w, owner, command, continuation)
}
