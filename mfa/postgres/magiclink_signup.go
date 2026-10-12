package mfapostgres

import (
	"context"
	"encoding/base64"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// InitializeMagicLinkSignup establishes empty factor authority only for the
// account genuinely created by this original consuming Work, after provisional
// capability consumption. Existing/missing/foreign registration evidence and
// duplicate initialization deny, never upsert or erase enrollment. Account,
// factor, proof and session effects must commit together under the coordinator.
func InitializeMagicLinkSignup(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || f.Operation.Owner != "identity/magiclink" || b.OperationID != "identity.magic-link.consume" || b.UserID != "" || b.AnonymousFlowID == "" || life.EventType != "session.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 0 {
		return invalidAuthority()
	}
	if _, err := w.MagicLinkConsumption(owner); err != nil {
		return err
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return invalidAuthority()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose)
SELECT r.tenant_id,r.user_id,1,0,r.command_id,r.purpose
FROM identity.registration_bindings r
JOIN identity.users u ON u.tenant_id=r.tenant_id AND u.user_id=r.user_id
JOIN identity.identifiers i ON i.tenant_id=r.tenant_id AND i.user_id=r.user_id AND i.identifier_id=r.identifier_id
WHERE r.tenant_id=$1 AND r.purpose='identity.magic-link.consume' AND r.command_id=$2 AND r.user_id=$3
AND r.credential_id IS NULL AND NOT r.accepted_only AND u.status='active' AND u.version=1
AND i.kind='email' AND i.verified AND i.verification_state=2 AND i.verification_version=1 AND i.verified_at IS NOT NULL`, string(b.TenantID), id, string(user))
	if err != nil {
		return identity.UnavailableError{}
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
