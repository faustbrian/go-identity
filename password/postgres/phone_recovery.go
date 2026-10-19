package passwordpostgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Replacement and removal conserve the same selected independent email/password
// path. Lock the actual eligible credential and email rows in the existing Work;
// a count, caller assertion or the changed phone cannot authorize either flow.
// This is the existing removal predicate, shared rather than weakened for send.
func requireIndependentPhoneRecovery(ctx context.Context, w kernel.Work, primary ActionPrimaryAdmission, tenant identity.TenantID, user identity.UserID, signinOwner *SigninService, resetOwner *ResetService) error {
	original, err := primary.Original()
	if err != nil {
		return err
	}
	b, err := original.Bindings()
	if err != nil || b.TenantID != tenant || b.UserID != user || signinOwner == nil || resetOwner == nil || resetOwner.request == nil {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT i.canonical_value FROM identity.identifiers i
JOIN identity.users u USING(tenant_id,user_id)
JOIN identity.credential_references c USING(tenant_id,user_id)
WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.kind='email'
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL AND u.status='active'
AND c.credential_id=$3 AND c.version=$4::numeric AND c.kind=1 AND c.owner='identity/password' AND c.enabled
AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
AND NOT EXISTS(SELECT 1 FROM identity.credential_references other
 WHERE other.tenant_id=c.tenant_id AND other.user_id=c.user_id AND other.kind=1
 AND other.owner='identity/password' AND other.credential_id<>c.credential_id)
ORDER BY i.is_primary DESC,i.identifier_id LIMIT 128 FOR SHARE OF u,i,c`, string(tenant), string(user), b.Authentication.CredentialID, strconv.FormatUint(original.EffectiveCredentialVersion(), 10))
	if err != nil {
		return err
	}
	defer rows.Close()
	usable := false
	for rows.Next() {
		var canonical string
		if rows.Scan(&canonical) != nil {
			return identity.UnavailableError{}
		}
		signin, first := signinOwner.address.Parse(email.AddressInput(canonical))
		reset, second := resetOwner.request.config.Address.Parse(email.AddressInput(canonical))
		if first == nil && second == nil && signin.Canonical().Record().Value == canonical && reset.Canonical().Record().Value == canonical {
			usable = true
		}
	}
	if rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if !usable {
		return identity.FinalAccessError{}
	}
	return ctx.Err()
}
