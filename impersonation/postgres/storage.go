package impersonationpostgres

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Envelopes contain the canonical encrypted request or decision, never a clear
// reason projection. The selected scope/reason limits fit within this bound.
const maxStoredPayloadBytes = 64 << 10

type grantRecord struct {
	tenant                 identity.TenantID
	id                     impersonation.GrantID
	requester, target      identity.UserID
	digest                 [32]byte
	payload                []byte
	requestedAt, expiresAt time.Time
	version                uint64
}

type approvalRecord struct {
	commandID identity.CommandID
	approver  identity.UserID
	payload   []byte
	decidedAt time.Time
}

const grantInsertSQL = `INSERT INTO identity_impersonation.grants
 (tenant_id,grant_id,requester_id,target_id,request_digest,encrypted_payload,requested_at,expires_at,state,version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending_approval',1)`

const grantSelectSQL = `SELECT tenant_id,grant_id,requester_id,target_id,request_digest,encrypted_payload,requested_at,expires_at,version
 FROM identity_impersonation.grants WHERE tenant_id=$1 AND grant_id=$2`

// The inserted decision depends on the successful exact CAS. A failed insert
// aborts that same statement/transaction, so no approved grant loses its row.
const grantApproveSQL = `WITH accepted AS (
 UPDATE identity_impersonation.grants SET state='approved',version=2
 WHERE tenant_id=$1 AND grant_id=$2 AND requester_id=$3 AND target_id=$4
  AND request_digest=$5 AND requested_at=$6 AND expires_at=$7
  AND state='pending_approval' AND version=1 AND requested_at<=$8 AND expires_at>$8
  AND $9<>requester_id AND $9<>target_id
  AND $11<>grant_id
 RETURNING tenant_id,grant_id,requester_id,target_id,request_digest
)
INSERT INTO identity_impersonation.approvals
 (tenant_id,grant_id,requester_id,target_id,request_digest,approver_id,encrypted_payload,decided_at,command_id)
 SELECT tenant_id,grant_id,requester_id,target_id,request_digest,$9,$10,$8,$11 FROM accepted`

const grantRequestRecoverySQL = `SELECT 1 FROM identity_impersonation.grants
 WHERE tenant_id=$1 AND grant_id=$2 AND requester_id=$3 AND target_id=$4`

const grantApprovalRecoverySQL = `SELECT 1 FROM identity_impersonation.approvals
 WHERE tenant_id=$1 AND grant_id=$2 AND command_id=$3 AND approver_id=$4 AND target_id=$5`

func grantInsertArgs(g grantRecord) []any {
	return []any{string(g.tenant), string(g.id), string(g.requester), string(g.target), g.digest[:], g.payload, g.requestedAt, g.expiresAt}
}

func grantApprovalArgs(g grantRecord, a approvalRecord) []any {
	return []any{string(g.tenant), string(g.id), string(g.requester), string(g.target), g.digest[:], g.requestedAt, g.expiresAt, a.decidedAt, string(a.approver), a.payload, string(a.commandID)}
}

func insertPendingGrant(ctx context.Context, w kernel.Work, g grantRecord) error {
	if ctx == nil || !validStoredGrant(g) || g.version != 1 {
		return invalidStorageInput()
	}
	count, err := w.Exec(ctx, grantInsertSQL, grantInsertArgs(g)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

// observeGrant is only a scoped preflight snapshot. The contributor must lock
// and compare it again in the coordinator's original Work before deciding.
func observeGrant(ctx context.Context, pool *database.Pool, tenant identity.TenantID, id impersonation.GrantID) (grantRecord, error) {
	if ctx == nil || pool == nil || !validStoredGrantKey(tenant, id) {
		return grantRecord{}, invalidStorageInput()
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	rows, err := pool.Raw().Query(bounded, grantSelectSQL, string(tenant), string(id))
	if err != nil {
		return grantRecord{}, storageReadError(bounded)
	}
	return decodeStoredGrant(bounded, rows)
}

func lockGrant(ctx context.Context, w kernel.Work, tenant identity.TenantID, id impersonation.GrantID) (grantRecord, error) {
	if ctx == nil || !validStoredGrantKey(tenant, id) {
		return grantRecord{}, invalidStorageInput()
	}
	rows, err := w.Query(ctx, grantSelectSQL+" FOR UPDATE", string(tenant), string(id))
	if err != nil {
		return grantRecord{}, err
	}
	return decodeStoredGrant(ctx, rows)
}

func saveApproval(ctx context.Context, w kernel.Work, g grantRecord, a approvalRecord) error {
	_, commandErr := identity.ParseCommandID(string(a.commandID))
	if ctx == nil || commandErr != nil || !validStoredGrant(g) || !validStorageID(string(a.approver)) || len(a.payload) == 0 || len(a.payload) > maxStoredPayloadBytes || !storageExactTime(a.decidedAt) {
		return invalidStorageInput()
	}
	if g.version != 1 || string(a.commandID) == string(g.id) || a.approver == g.requester || a.approver == g.target || a.decidedAt.Before(g.requestedAt) {
		return impersonation.ErrConflict
	}
	if !a.decidedAt.Before(g.expiresAt) {
		return impersonation.ErrExpired
	}
	count, err := w.Exec(ctx, grantApproveSQL, grantApprovalArgs(g, a)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

// The native contributor verifies its exact recovery invocation before calling
// this evidence reader. Retained immutable rows identify the original effect,
// even after expiry; they neither reconstruct a receipt nor authorize a retry.
func recoverGrantEffect(ctx context.Context, w kernel.RecoveryWork, binding identity.CommandBinding) (kernel.RecoveryStatus, error) {
	if ctx == nil {
		return kernel.RecoveryUnknown, invalidStorageInput()
	}
	query, args, err := grantRecoveryQuery(binding)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, query, args...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return decodeGrantEffect(ctx, rows)
}

func grantRecoveryQuery(binding identity.CommandBinding) (string, []any, error) {
	op, selected := approvalOperation(binding.OperationID)
	if !selected || binding.ValidateFor(op) != nil || binding.ActorKind != authorization.SubjectUser || identity.UserID(binding.ActorID) == binding.UserID || !validStoredGrantKey(binding.TenantID, impersonation.GrantID(binding.RecordID)) {
		return "", nil, invalidStorageInput()
	}
	if binding.OperationID == requestAction {
		if string(binding.CommandID) != binding.RecordID {
			return "", nil, invalidStorageInput()
		}
		return grantRequestRecoverySQL, []any{string(binding.TenantID), binding.RecordID, string(binding.ActorID), string(binding.UserID)}, nil
	}
	if string(binding.CommandID) == binding.RecordID {
		return "", nil, invalidStorageInput()
	}
	return grantApprovalRecoverySQL, []any{string(binding.TenantID), binding.RecordID, string(binding.CommandID), string(binding.ActorID), string(binding.UserID)}, nil
}

func decodeGrantEffect(ctx context.Context, rows storedGrantRows) (kernel.RecoveryStatus, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, storageReadError(ctx)
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var effect int32
	if rows.Scan(&effect) != nil || effect != 1 || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, storageReadError(ctx)
	}
	return kernel.RecoveryCommitted, nil
}

type storedGrantRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

func decodeStoredGrant(ctx context.Context, rows storedGrantRows) (grantRecord, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return grantRecord{}, storageReadError(ctx)
		}
		return grantRecord{}, impersonation.ErrConflict
	}
	var tenant, id, requester, target string
	var digest []byte
	var version int16
	var g grantRecord
	if err := rows.Scan(&tenant, &id, &requester, &target, &digest, &g.payload, &g.requestedAt, &g.expiresAt, &version); err != nil {
		return grantRecord{}, storageReadError(ctx)
	}
	g.tenant, g.id = identity.TenantID(tenant), impersonation.GrantID(id)
	g.requester, g.target = identity.UserID(requester), identity.UserID(target)
	if len(digest) != len(g.digest) || version < 1 || version > 2 {
		return grantRecord{}, identity.UnavailableError{}
	}
	copy(g.digest[:], digest)
	g.version = uint64(version)
	g.requestedAt, g.expiresAt = g.requestedAt.UTC(), g.expiresAt.UTC()
	if rows.Next() || rows.Err() != nil || !validStoredGrant(g) {
		return grantRecord{}, storageReadError(ctx)
	}
	return g, nil
}

func validStoredGrant(g grantRecord) bool {
	return validStoredGrantKey(g.tenant, g.id) && validStorageID(string(g.requester)) && validStorageID(string(g.target)) && g.requester != g.target && len(g.payload) > 0 && len(g.payload) <= maxStoredPayloadBytes && storageExactTime(g.requestedAt) && storageExactTime(g.expiresAt) && g.expiresAt.Sub(g.requestedAt) == impersonation.ApprovalLifetime && (g.version == 1 || g.version == 2)
}

func validStoredGrantKey(tenant identity.TenantID, id impersonation.GrantID) bool {
	_, err := identity.ParseCommandID(string(id))
	return err == nil && validStorageID(string(tenant))
}

func validStorageID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func storageExactTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

func invalidStorageInput() error {
	return identity.InvalidInputError{Field: "impersonation_grant"}
}

func storageReadError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return identity.UnavailableError{}
}
