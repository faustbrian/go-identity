package passwordpostgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// PasskeyRemovalRecoverySource borrows the fully configured native emailed
// password-reset request/completion owner. It checks current verified recovery
// email and consistent usable password material in the protected parent's Work,
// never issuing a reset, sending mail or opening another transaction. Keep the
// borrowed owner and its dependencies alive and immutable during all calls.
type PasskeyRemovalRecoverySource struct{ reset *ResetService }

// NewPasskeyRemovalRecoverySource selects actual native request/completion
// configuration without IO. Completion-only and unconfigured owners deny.
// Before use, the native deletion constructor must also require Matches for its
// actual primary pool, password-session realm and policy revision.
func NewPasskeyRemovalRecoverySource(reset *ResetService) (*PasskeyRemovalRecoverySource, error) {
	if _, err := NewFactorRemovalRecoverySource(reset); err != nil {
		return nil, err
	}
	return &PasskeyRemovalRecoverySource{reset: reset}, nil
}

// PasskeyRemovalRecoveryIdentity returns immutable selected reset configuration
// identity, not a recovery proof or a renewable authority observation. Zero is
// unconfigured. The original native command must bind Fields unchanged.
func (s *PasskeyRemovalRecoverySource) PasskeyRemovalRecoveryIdentity() [32]byte {
	if s == nil || s.reset == nil || s.reset.request == nil {
		return [32]byte{}
	}
	return s.reset.request.profile
}

// Matches checks trusted startup compatibility without IO: the identical primary
// pool, session schema, global/policy namespace and password action policy must
// agree. This prevents selecting a reset owner for a different account realm.
// It neither authenticates a session nor establishes runtime recovery readiness.
func (s *PasskeyRemovalRecoverySource) Matches(pool *database.Pool, c sessionpg.SessionServiceConfig, policyID string, version uint64) bool {
	if s.PasskeyRemovalRecoveryIdentity() == ([32]byte{}) || s.reset.config == nil || pool == nil || s.reset.pool != pool {
		return false
	}
	r := s.reset.config()
	return r.Coordinator.AdmissionPolicy != nil && version != 0 && policyID == r.PolicyID && version == r.Coordinator.AdmissionPolicy.PolicyVersion && c.Repository.Schema == r.Session.Schema && c.Profile.GlobalAuthorityID == r.GlobalAuthorityID && c.Profile.PolicyNamespace == r.AuthorizationNamespace && c.Profile.AuthenticationMethod == "password" && c.Profile.CredentialKind == identity.CredentialPassword && c.Profile.CredentialOwner == "identity/password"
}

// Fields returns an owned non-secret binding to the configured reset path for
// the original deletion command. It grants no authentication or recovery use.
func (s *PasskeyRemovalRecoverySource) Fields() ([]identity.FeatureField, error) {
	id := s.PasskeyRemovalRecoveryIdentity()
	if id == ([32]byte{}) {
		return nil, password.ErrPasswordWork
	}
	return []identity.FeatureField{{Name: "passkey-removal.recovery", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(id[:])}}}, nil
}

// CheckPasskeyRemovalRecovery fences the selected recovery path for exact
// self-user native deletion. The parent must abort on any error and repeat this
// check during final admission. It locks verified email, active user, unique
// enabled password reference and matching real password material in the same
// Work; expiry is checked using primary time after locks. Missing, corrupt,
// unverified, disabled, expired, unavailable or foreign state denies. No hash,
// reset credential, session or continuing permission is returned.
func (s *PasskeyRemovalRecoverySource) CheckPasskeyRemovalRecovery(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || s.PasskeyRemovalRecoveryIdentity() == ([32]byte{}) {
		return password.ErrPasswordWork
	}
	b, f, lifecycle, err := w.FeatureScope(owner)
	spec, ok := c.Feature()
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || !ok || spec.Binding != b || spec.Operation != op || f.Operation != op || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || f.Contributor != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) || lifecycle.EventType != "identity.passkey.remove_credential" || lifecycle.BeforeVersion == 0 || lifecycle.BeforeVersion == ^uint64(0) || lifecycle.AfterVersion != lifecycle.BeforeVersion+1 {
		return identity.ForbiddenError{}
	}
	profile, selected := s.PasskeyRemovalRecoveryIdentity(), false
	for _, field := range spec.Fields {
		if field.Name != "passkey-removal.recovery" {
			continue
		}
		v := field.Value
		if selected || v.Kind != identity.FeatureBytes || !bytes.Equal(v.Bytes, profile[:]) || v.Text != "" || v.Uint64 != 0 || v.Int64 != 0 || v.Bool || v.Time != (time.Time{}) {
			return identity.ForbiddenError{}
		}
		selected = true
	}
	if !selected {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.reset.config().Repository.MaximumDuration)
	defer stop()
	// Matching material/reference versions are necessary: directory metadata
	// alone cannot prove the configured reset owner has a usable predecessor.
	rows, err := w.Query(bounded, `SELECT CASE WHEN octet_length(i.canonical_value)<=4096 THEN i.canonical_value ELSE '' END,u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,
c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at,
p.version::text,p.algorithm,CASE WHEN octet_length(p.encoded_hash)<=$3 THEN p.encoded_hash ELSE '' END,p.created_at,p.updated_at
FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id)
JOIN identity.credential_references c USING(tenant_id,user_id)
JOIN identity_password.credentials p ON p.tenant_id=c.tenant_id AND p.user_id=c.user_id AND p.credential_id=c.credential_id
WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.kind='email' AND i.verified
AND i.verification_state=2 AND i.verified_at IS NOT NULL AND u.status='active'
AND c.kind=1 AND c.owner='identity/password' AND c.enabled
AND NOT EXISTS(SELECT 1 FROM identity.credential_references other WHERE other.tenant_id=c.tenant_id AND other.user_id=c.user_id AND other.kind=1 AND other.owner='identity/password' AND other.credential_id<>c.credential_id)
ORDER BY i.is_primary DESC,i.identifier_id LIMIT 1 FOR SHARE OF u,i,c,p`, string(b.TenantID), string(b.UserID), s.reset.repository.limits.EncodedHashBytes)
	if err != nil {
		return identity.UnavailableError{}
	}
	var row credentialRow
	var address string
	var expiry *time.Time
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&address, &row.tenant, &row.user, &row.status, &row.userVersion, &row.epoch, &row.id, &row.kind, &row.owner, &row.referenceVersion, &row.enabled, &expiry, &row.materialVersion, &row.algorithm, &row.hash, &row.created, &row.updated)
	if rows.Next() {
		err = password.ErrPasswordWork
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return identity.UnavailableError{}
	}
	if expiry != nil {
		row.expiry.Time, row.expiry.Valid = *expiry, true
	}
	parsed, err := s.reset.request.config.Address.Parse(email.AddressInput(address))
	if err != nil || parsed.Canonical().Record().Value != address {
		return identity.ForbiddenError{}
	}
	snapshot, err := decodeCredential(password.CredentialKey{TenantID: b.TenantID, SubjectID: b.UserID}, row, s.reset.repository.limits)
	if err != nil {
		return identity.UnavailableError{}
	}
	current := snapshot.Authority()
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if identity.CheckCredentialAuthority(current, current.Credential, current.AuthorityVersion, now) != nil {
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}

// Format redacts borrowed reset configuration and account correlation.
func (PasskeyRemovalRecoverySource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PasskeyRemovalRecoverySource(redacted)"))
}

// MarshalJSON prohibits implicit owner/configuration export.
func (PasskeyRemovalRecoverySource) MarshalJSON() ([]byte, error) {
	return nil, password.ErrPasswordWork
}

// MarshalText prohibits implicit owner/configuration export.
func (PasskeyRemovalRecoverySource) MarshalText() ([]byte, error) {
	return nil, password.ErrPasswordWork
}
