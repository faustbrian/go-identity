package impersonationpostgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Deny is separate from revoke. Only the exact unexpired pending request can
// gain a terminal denial, after both legacy-writer fences are installed.
const denialPendingSQL = `SELECT 1 FROM identity_impersonation.grants g
 WHERE g.tenant_id=$1 AND g.grant_id=$2 AND g.state='pending_approval' AND g.version=1
 AND g.expires_at>clock_timestamp() AND identity_impersonation.denial_ready()
 AND NOT EXISTS (SELECT 1 FROM identity_impersonation.denials d WHERE d.tenant_id=g.tenant_id AND d.grant_id=g.grant_id)
 AND NOT EXISTS (SELECT 1 FROM identity_impersonation.revocations r WHERE r.tenant_id=g.tenant_id AND r.grant_id=g.grant_id)`

const denialInsertSQL = `INSERT INTO identity_impersonation.denials
 (tenant_id,grant_id,command_id,denier_id,requester_id,target_id,request_digest,policy_id,policy_version,before_version,after_version,encrypted_payload,denied_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,1,2,$10,$11) ON CONFLICT DO NOTHING`

const denialRecoverySQL = `SELECT 1 FROM identity_impersonation.denials WHERE tenant_id=$1 AND grant_id=$2
 AND command_id=$3 AND denier_id=$4 AND target_id=$5 AND policy_id=$6 AND policy_version=$7::text::numeric
 AND before_version=1 AND after_version=2`

func (s *Service) requirePendingDenial(ctx context.Context, b identity.CommandBinding) error {
	rows, err := s.pool.Raw().Query(ctx, denialPendingSQL, denialKeyArgs(b)...)
	if err != nil {
		return storageReadError(ctx)
	}
	return requireDenialPendingRow(ctx, rows, b.CommandID)
}

func denialKeyArgs(b identity.CommandBinding) []any {
	return []any{string(b.TenantID), b.RecordID}
}

func requireDenialPendingRow(ctx context.Context, rows storedGrantRows, command identity.CommandID) error {
	status, err := decodeGrantEffect(ctx, rows)
	if err != nil {
		return err
	}
	if status != kernel.RecoveryCommitted {
		return identity.ConflictError{CommandID: command}
	}
	return nil
}

func denialInsertArgs(g grantRecord, b identity.CommandBinding, d denialIntent, at time.Time) []any {
	return []any{string(g.tenant), string(g.id), string(b.CommandID), string(b.ActorID), string(g.requester), string(g.target),
		g.digest[:], b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), d.payload, at}
}

// The original grant row is already locked by this Work. The readiness and
// terminal checks run under that lock, and the marker, audit, lifecycle and
// receipt then commit in the same transaction.
func storeDenial(ctx context.Context, w kernel.Work, g grantRecord, b identity.CommandBinding, d denialIntent, at time.Time) error {
	op, _ := approvalOperation(denyAction)
	if ctx == nil || b.ValidateFor(op) != nil || b.TenantID != g.tenant || b.RecordID != string(g.id) || b.UserID != g.target ||
		b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == g.target || identity.UserID(b.ActorID) == g.requester ||
		g.version != 1 || len(d.payload) == 0 || len(d.payload) > maximumCustodyEnvelope || !storageExactTime(at) || at.Before(g.requestedAt) {
		return invalidStorageInput()
	}
	rows, err := w.Query(ctx, denialPendingSQL, denialKeyArgs(b)...)
	if err != nil {
		return err
	}
	if err := requireDenialPendingRow(ctx, rows, b.CommandID); err != nil {
		return err
	}
	count, err := w.Exec(ctx, denialInsertSQL, denialInsertArgs(g, b, d, at)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

func denialRecoveryArgs(b identity.CommandBinding) []any {
	return []any{string(b.TenantID), b.RecordID, string(b.CommandID), string(b.ActorID), string(b.UserID),
		b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10)}
}

func recoverDenialEffect(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding) (kernel.RecoveryStatus, error) {
	op, _ := approvalOperation(denyAction)
	if ctx == nil || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == b.UserID ||
		!validStoredGrantKey(b.TenantID, impersonation.GrantID(b.RecordID)) || b.RecordID == string(b.CommandID) {
		return kernel.RecoveryUnknown, invalidStorageInput()
	}
	rows, err := w.Query(ctx, denialRecoverySQL, denialRecoveryArgs(b)...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return decodeGrantEffect(ctx, rows)
}
