package passwordpostgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// FactorRemovalRecoverySource borrows a fully selected native emailed-password-
// reset request/completion owner. It fences usable verified email and password
// authority in the MFA owner's existing Work; it never opens a transaction,
// reads password/factor material, issues a reset or retains Work. Keep the native
// owner and its selected delivery dependencies alive while management is used.
type FactorRemovalRecoverySource struct{ reset *ResetService }

// NewFactorRemovalRecoverySource performs no IO and rejects completion-only or
// unconfigured reset services. The native MFA owner must independently verify
// the original primary/factor proof, actual session and current action policy.
func NewFactorRemovalRecoverySource(reset *ResetService) (*FactorRemovalRecoverySource, error) {
	if reset == nil || reset.config == nil || reset.request == nil || reset.request.profile == ([32]byte{}) || reset.configuration == ([32]byte{}) || reset.repository == nil || reset.directory == nil {
		return nil, password.ErrPasswordWork
	}
	return &FactorRemovalRecoverySource{reset: reset}, nil
}

// FactorRemovalRecoveryIdentity is the immutable selected native request and
// completion configuration fingerprint, not a recovery proof or credential.
func (s *FactorRemovalRecoverySource) FactorRemovalRecoveryIdentity() [32]byte {
	if s == nil || s.reset == nil || s.reset.request == nil {
		return [32]byte{}
	}
	return s.reset.request.profile
}

// CheckFactorRemovalRecovery fences current usable email recovery for exact
// self factor-removal Work. The coordinator owns tenant serialization and the
// retained account/identifier/credential row locks. Missing or unverified email,
// blocked user, disabled/expired password, outage and unsupported scope deny.
// Success grants no factor mutation, proof use, continuing session or reset.
func (s *FactorRemovalRecoverySource) CheckFactorRemovalRecovery(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || s.FactorRemovalRecoveryIdentity() == ([32]byte{}) {
		return password.ErrPasswordWork
	}
	b, f, _, err := w.FeatureScope(owner)
	spec, ok := c.Feature()
	disable := b.OperationID == "identity.mfa.disable" && b.SchemaID == "mfa-disable"
	update := b.OperationID == "identity.mfa.factor-update" && b.SchemaID == "mfa-factor-update"
	if err != nil || !ok || spec.Binding != b || spec.Operation != f.Operation || !update && !disable || b.SchemaVersion != 1 || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return identity.ForbiddenError{}
	}
	selected := false
	for _, field := range spec.Fields {
		if field.Name == "factor.action" {
			if selected || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != uint64(mfa.Remove) {
				return identity.ForbiddenError{}
			}
			selected = true
		}
	}
	if !selected {
		return identity.ForbiddenError{}
	}
	if disable {
		target := false
		for _, field := range spec.Fields {
			if field.Name == "disable.target" {
				if target || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != uint64(mfa.OneFactor) && field.Value.Uint64 != uint64(mfa.AllFactors) {
					return identity.ForbiddenError{}
				}
				target = true
			}
		}
		if !target {
			return identity.ForbiddenError{}
		}
	}
	bounded, stop := context.WithTimeout(ctx, s.reset.config().Repository.MaximumDuration)
	defer stop()
	rows, err := w.Query(bounded, `SELECT i.identifier_id FROM identity.identifiers i
JOIN identity.users u USING(tenant_id,user_id)
JOIN identity.credential_references c USING(tenant_id,user_id)
WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.kind='email' AND i.verified
AND i.verification_state=2 AND i.verified_at IS NOT NULL AND u.status='active'
AND c.kind=1 AND c.owner='identity/password' AND c.enabled
AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
AND NOT EXISTS(SELECT 1 FROM identity.credential_references other
 WHERE other.tenant_id=c.tenant_id AND other.user_id=c.user_id
 AND other.kind=1 AND other.owner='identity/password'
 AND other.credential_id<>c.credential_id)
ORDER BY i.is_primary DESC,i.identifier_id,c.credential_id LIMIT 1 FOR SHARE OF u,i,c`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	var id string
	if rows.Scan(&id) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if _, err := identity.ParseIdentifierID(id); err != nil {
		return identity.UnavailableError{}
	}
	return bounded.Err()
}

// Format prevents implicit native owner or deployment-policy disclosure.
func (FactorRemovalRecoverySource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.FactorRemovalRecoverySource(redacted)"))
}

var _ mfapg.FactorRemovalRecoverySource = (*FactorRemovalRecoverySource)(nil)
