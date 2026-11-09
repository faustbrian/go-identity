package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The RP transaction remains the original state's resource; the root owns a
// different, already allocated account record and callback command. Deriving
// this metadata cannot reserve state, release PKCE or authorize a link.
func callbackSpecification(flow rpCallbackFlow) (identity.AccountLinkPreparationCommand, error) {
	b := flow.binding.Input.binding()
	original, err := flow.original.Bindings()
	if err != nil || original.TenantID != b.TenantID || original.UserID != b.UserID || b.OperationID != "identity.account.link-start" || flow.binding.Provider.ID == "" || flow.binding.Provider.Version == 0 || flow.binding.AccountRecordID == "" || flow.binding.AccountRecordID == b.RecordID {
		return identity.AccountLinkPreparationCommand{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(flow.binding.CallbackCommandID)); err != nil {
		return identity.AccountLinkPreparationCommand{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(flow.binding)
	if err != nil {
		return identity.AccountLinkPreparationCommand{}, identity.ForbiddenError{}
	}
	defer clear(frame)
	spec := identity.AccountLinkPreparationCommand{ProviderID: flow.binding.Provider.ID, ProviderConfigVersion: flow.binding.Provider.Version, FlowID: b.RecordID, FlowFingerprint: sha256.Sum256(frame), SessionID: original.SessionID, SessionVersion: original.Version}
	b.CommandID, b.RecordID, b.CorrelationID = flow.binding.CallbackCommandID, flow.binding.AccountRecordID, string(flow.binding.CallbackCommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion, b.LinkMode = "identity.account.link-token", "identity-account", 1, identity.AccountLinkExplicit
	spec.Binding = b
	return spec, nil
}

// Only own RP rows are read here. All user, session, factor, proof and counter
// fences remain with their existing owners in the same borrowed transaction.
func (s *LinkService) requireCallbackTransaction(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
}, flow rpCallbackFlow, now time.Time) error {
	if flow.erased || now.Before(flow.binding.IssuedAt) || !now.Before(flow.binding.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	b, p := flow.binding.Input.binding(), flow.binding.Provider
	original, err := flow.original.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	rows, err := q.Query(ctx, `SELECT transaction_id FROM `+rpQuotedSchema(s.config().Schema)+`.transactions
 WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND user_id=$4
 AND operation='identity.account.link-start' AND preauth_id IS NULL
 AND session_id=$5 AND session_version=$6::numeric AND provider_id=$7
 AND configuration_version=$8::numeric AND issuer=$9 AND client_id=$10
 AND redirect_uri=$11 AND response_mode='query' AND state_key_version=$12
 AND state_digest=$13 AND pkce_key_version=$14 AND pkce_commitment=$15
 AND issued_at=$16 AND expires_at=$17 AND version=1 AND secrets_erased_at IS NULL
 AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL FOR UPDATE`, string(b.TenantID), b.RecordID, id, string(b.UserID), original.SessionID, original.Version, p.ID, p.Version, p.Issuer, p.ClientID, p.RedirectURI, flow.binding.StateKeyVersion, flow.binding.StateDigest[:], flow.binding.PKCEKeyVersion, flow.binding.PKCECommitment[:], flow.binding.IssuedAt, flow.binding.ExpiresAt)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	var selected string
	if rows.Scan(&selected) != nil || selected != b.RecordID || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}
