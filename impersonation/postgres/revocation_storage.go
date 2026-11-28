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

// All three relations are anchored on the exact tenant/grant primary key.
// The original v1 row is intent history; an active version comes from v2.
// The readiness function is installed only with the final legacy-writer fence.
const revocableVersionSQL = `SELECT coalesce(a.version,g.version)::integer
 FROM identity_impersonation.grants g
 LEFT JOIN identity_impersonation.active_grants a ON a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id
 WHERE g.tenant_id=$1 AND g.grant_id=$2 AND (a.state IS NULL OR a.state='active')
 AND NOT EXISTS (SELECT 1 FROM identity_impersonation.revocations r WHERE r.tenant_id=g.tenant_id AND r.grant_id=g.grant_id)
 AND identity_impersonation.revocation_ready()`

const revocationActiveSQL = `UPDATE identity_impersonation.active_grants SET state='revoked',version=4
 WHERE tenant_id=$1 AND grant_id=$2 AND actor_id=$3 AND target_id=$4 AND request_digest=$5 AND state='active' AND version=3`

const revocationInsertSQL = `INSERT INTO identity_impersonation.revocations
 (tenant_id,grant_id,command_id,revoker_id,requester_id,target_id,request_digest,policy_id,policy_version,before_version,after_version,encrypted_payload,revoked_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11,$12,$13) ON CONFLICT DO NOTHING`

const revocationRecoverySQL = `SELECT 1 FROM identity_impersonation.revocations WHERE tenant_id=$1 AND grant_id=$2
 AND command_id=$3 AND revoker_id=$4 AND target_id=$5 AND policy_id=$6 AND policy_version=$7::text::numeric
 AND before_version=$8 AND after_version=$9`

func requireRevocableVersion(ctx context.Context, rows storedGrantRows, expected uint64) error {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return storageReadError(ctx)
		}
		return impersonation.ErrConflict
	}
	var version int32
	if err := rows.Scan(&version); err != nil || rows.Next() || rows.Err() != nil || version < 1 || version > 3 {
		return storageReadError(ctx)
	}
	if uint64(version) != expected {
		return impersonation.ErrConflict
	}
	return nil
}

func revocationActiveArgs(g grantRecord) []any {
	return []any{string(g.tenant), string(g.id), string(g.requester), string(g.target), g.digest[:]}
}

func revocationInsertArgs(g grantRecord, b identity.CommandBinding, r revocationIntent, at time.Time) []any {
	return []any{string(g.tenant), string(g.id), string(b.CommandID), string(b.ActorID), string(g.requester), string(g.target),
		g.digest[:], b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), int16(r.before), int16(r.before + 1), r.payload, at}
}

// The owner already holds the grant row lock shared by approval and start.
// Updating active authority and storing terminal command provenance share
// native Work with audit, outbox and journal effects.
func storeRevocation(ctx context.Context, w kernel.Work, g grantRecord, b identity.CommandBinding, r revocationIntent, at time.Time) error {
	op, _ := approvalOperation(revokeAction)
	if ctx == nil || b.ValidateFor(op) != nil || b.TenantID != g.tenant || b.RecordID != string(g.id) || b.UserID != g.target ||
		b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == g.target ||
		r.before < 1 || r.before > 3 || r.before < 3 && r.before != g.version || r.before == 3 && g.version != 2 ||
		len(r.payload) == 0 || len(r.payload) > maximumCustodyEnvelope || !storageExactTime(at) || at.Before(g.requestedAt) {
		return invalidStorageInput()
	}
	if r.before == 3 {
		count, err := w.Exec(ctx, revocationActiveSQL, revocationActiveArgs(g)...)
		if err != nil {
			return err
		}
		if count != 1 {
			return impersonation.ErrConflict
		}
	}
	count, err := w.Exec(ctx, revocationInsertSQL, revocationInsertArgs(g, b, r, at)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

func revocationRecoveryArgs(b identity.CommandBinding, l kernel.LifecyclePlan) []any {
	return []any{string(b.TenantID), b.RecordID, string(b.CommandID), string(b.ActorID), string(b.UserID),
		b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), int16(l.BeforeVersion), int16(l.AfterVersion)}
}

func recoverRevocationEffect(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding, l kernel.LifecyclePlan) (kernel.RecoveryStatus, error) {
	op, _ := approvalOperation(revokeAction)
	if ctx == nil || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == b.UserID ||
		!validStoredGrantKey(b.TenantID, impersonation.GrantID(b.RecordID)) || b.RecordID == string(b.CommandID) ||
		l.BeforeVersion < 1 || l.BeforeVersion > 3 || l != revocationLifecycle(l.BeforeVersion) {
		return kernel.RecoveryUnknown, invalidStorageInput()
	}
	rows, err := w.Query(ctx, revocationRecoverySQL, revocationRecoveryArgs(b, l)...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return decodeGrantEffect(ctx, rows)
}
