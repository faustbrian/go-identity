package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// SelectResetRecipientCredential selects the original verified email/password
// snapshot only inside the exact native anonymous reset-request invocation.
// It contains no verifier and grants no factor/risk/issuance authority. Missing,
// blocked, unverified or password-free selections return a suppressed record.
// The caller must still invoke RequireResetRecipientCredential and the factor
// owner before generation, and repeat their fences at final application.
// Work owns SQL, cancellation, row closure and transaction lifetime; no pool,
// callback, mutation, missing-factor inference or reusable validity lease is
// created. Multiple password references and malformed primary state deny.
func (w Work) SelectResetRecipientCredential(ctx context.Context, owner FeaturePreparationContributor, q RecipientQuery) (recipient RecipientRecord, credential CredentialAdmission, enabled bool, err error) {
	b, f, _, err := w.FeatureScope(owner)
	if ctx == nil || err != nil || !passwordResetRequestOperation(f.Operation) || f.Contributor.Owner != "identity/password/postgres" || f.Contributor.ContractID != "identity.password" || f.Contributor.Version != 1 || b.UserID != "" || q.UserID != "" || q.TenantID != b.TenantID || q.Kind != identity.IdentifierEmail || q.Eligibility != RecipientVerified || q.Validate() != nil {
		return recipient, credential, false, invalidWork()
	}
	rows, err := w.Query(ctx, recipientSelection(q), string(q.TenantID), string(q.Kind), q.CanonicalValue)
	if err != nil {
		return recipient, credential, false, err
	}
	recipient, err = readRecipient(q, rows)
	rows.Close()
	if err != nil {
		return RecipientRecord{}, credential, false, err
	}
	if recipient.Suppressed {
		return recipient, credential, false, nil
	}
	rows, err = w.Query(ctx, `SELECT credential_id,version::text,enabled,expires_at FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND kind=1 AND owner='identity/password' LIMIT 2`, string(q.TenantID), string(recipient.User.ID))
	if err != nil {
		return RecipientRecord{}, credential, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return RecipientRecord{}, credential, false, rows.Err()
		}
		return RecipientRecord{Query: q, Suppressed: true}, credential, false, nil
	}
	var id, version string
	var expires *time.Time
	if err = rows.Scan(&id, &version, &enabled, &expires); err != nil {
		return RecipientRecord{}, credential, false, err
	}
	if rows.Next() || rows.Err() != nil {
		return RecipientRecord{}, credential, false, identity.UnavailableError{}
	}
	value, err := strconv.ParseUint(version, 10, 64)
	if err != nil || value == 0 {
		return RecipientRecord{}, credential, false, identity.UnavailableError{}
	}
	if expires != nil && !postgresExactTime(*expires) {
		return RecipientRecord{}, credential, false, identity.UnavailableError{}
	}
	if expires != nil && !recipient.ObservedAt.Before(*expires) {
		return RecipientRecord{Query: q, Suppressed: true}, credential, false, nil
	}
	credential = CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(id), TenantID: q.TenantID, UserID: recipient.User.ID, Owner: "identity/password", Kind: identity.CredentialPassword, Version: value}, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierAuthorityVersion: recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: recipient.CredentialAuthorityVersion}
	if credential.Credential.Validate(q.TenantID, recipient.User.ID) != nil {
		return RecipientRecord{}, CredentialAdmission{}, false, identity.UnavailableError{}
	}
	return recipient, credential, enabled, nil
}
