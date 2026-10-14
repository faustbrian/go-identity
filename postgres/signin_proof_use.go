package postgres

import (
	"context"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// stageSignInProofUse is private provisional custody storage, not proof
// verification or session authority. The protected issuer must first validate
// the original opaque proof with its configured authenticator and freeze its
// complete metadata in the original command. Current authority checks and final
// temporal revalidation remain separate mandatory phases. No public issuer is
// enabled by this helper. Work owns rollback/commit and all participant effects.
// authority is a stable trusted source namespace: authentication ProofID
// equality has meaning only within that namespace. Version never makes a used
// proof ID reusable. Rows are retained tombstones, not a prunable session cache.
func (w Work) stageSignInProofUse(ctx context.Context, authority, proofID string, version uint64, expires time.Time) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func(err error) error { return w.fail(w.state.ctx, err) }
	operation := identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if ctx == nil || w.state.binding.ValidateFor(operation) != nil || !queryScopeText(authority) || !visibleProofID(proofID) || version == 0 || expires.IsZero() || expires.UTC().Year() < 1 || expires.UTC().Year() > 9999 {
		return fail(invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(w.state.binding.CommandID))
	n, err := w.Exec(ctx, `INSERT INTO identity.signin_proof_uses(authority_id,proof_id,proof_version,command_id,tenant_id,user_id,session_id,expires_at)
 VALUES($1,$2,$3::numeric,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, authority, proofID, version, id, string(w.state.binding.TenantID), string(w.state.binding.UserID), w.state.binding.RecordID, expires.UTC().Format(signInExpiryLayout))
	if err != nil {
		return fail(err)
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	// The insert may wait for an uncommitted conflicting use to roll back.
	// Statement/transaction start time would accept a proof that expired while
	// waiting. Recheck primary time only after that uniqueness lock is acquired.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return fail(err)
	}
	if !now.Before(expires) {
		return fail(identity.ForbiddenError{})
	}
	return nil
}

const signInExpiryLayout = "2006-01-02T15:04:05.000000000Z"

func visibleProofID(id string) bool {
	if len(id) < 22 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
