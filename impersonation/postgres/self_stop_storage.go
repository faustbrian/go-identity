package impersonationpostgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const stopActiveSQL = `UPDATE identity_impersonation.active_grants SET state='stopped',version=4
 WHERE tenant_id=$1 AND grant_id=$2 AND activation_command_id=$3 AND state='active' AND version=3`
const stopInsertSQL = `INSERT INTO identity_impersonation.stops
 (tenant_id,grant_id,command_id,activation_command_id,actor_id,target_id,policy_id,policy_version,stopped_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8::text::numeric,$9) ON CONFLICT DO NOTHING`
const stopRecoverySQL = `SELECT 1 FROM identity_impersonation.stops WHERE tenant_id=$1 AND grant_id=$2
 AND command_id=$3 AND actor_id=$4 AND target_id=$5 AND policy_id=$6 AND policy_version=$7::text::numeric`

func stopActiveArgs(row activationRecord) []any {
	return []any{string(row.tenant), string(row.grantID), string(row.commandID)}
}

func stopInsertArgs(b identity.CommandBinding, row activationRecord, at time.Time) []any {
	return []any{string(b.TenantID), b.RecordID, string(b.CommandID), string(row.commandID), string(row.actor),
		string(row.target), b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), at}
}

func stopRecoveryArgs(b identity.CommandBinding) []any {
	return []any{string(b.TenantID), b.RecordID, string(b.CommandID), string(b.ActorID), string(b.UserID),
		b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10)}
}

func (p *approvalPhase) checkStopWork(ctx context.Context, w kernel.Work, want impersonation.Status) (time.Time, error) {
	if p.stop == nil || !p.service.selfStop || !p.stop.matches(p.binding) {
		return time.Time{}, identity.ForbiddenError{}
	}
	frozen := p.stop.row
	digest := frozen.derivedDigest
	rows, err := w.Query(ctx, activationSelectSQL, string(frozen.tenant), strconv.FormatUint(uint64(digest.KeyVersion), 10), digest.Sum[:])
	if err != nil {
		return time.Time{}, err
	}
	row, err := decodeActivation(ctx, rows)
	if err != nil {
		return time.Time{}, err
	}
	if row.status != want {
		return time.Time{}, identity.ConflictError{CommandID: p.binding.CommandID}
	}
	row.status, row.version = frozen.status, frozen.version
	if !sameActiveAuthority(row, frozen) {
		return time.Time{}, identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, stopProofSelectSQL, string(row.tenant), string(row.grantID))
	if err != nil {
		return time.Time{}, err
	}
	proof, err := loadStopProof(ctx, rows, row)
	if err != nil {
		return time.Time{}, err
	}
	if proof != p.stop.proof || checkStopProof(proof, p.stop.csrf, p.service.config.CSRFKey) != nil {
		return time.Time{}, identity.ForbiddenError{}
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !p.stop.unexpired(at) {
		return time.Time{}, identity.ConflictError{CommandID: p.binding.CommandID}
	}
	return at.UTC(), nil
}

// The shared original grant lock serializes this transition with revoke.
// Native Work commits the active CAS and stop provenance with the normal
// audit, outbox and journal. The old activation reader sees terminal state.
func (p *approvalPhase) storeStop(ctx context.Context, w kernel.Work, locked grantRecord, at time.Time) error {
	row := p.stop.row
	if locked.tenant != row.tenant || locked.id != row.grantID || locked.requester != row.actor ||
		locked.target != row.target || locked.digest != row.requestDigest || locked.version != 2 {
		return identity.ForbiddenError{}
	}
	count, err := w.Exec(ctx, stopActiveSQL, stopActiveArgs(row)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{CommandID: p.binding.CommandID}
	}
	count, err = w.Exec(ctx, stopInsertSQL, stopInsertArgs(p.binding, row, at)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{CommandID: p.binding.CommandID}
	}
	return nil
}

func recoverStopEffect(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding) (kernel.RecoveryStatus, error) {
	rows, err := w.Query(ctx, stopRecoverySQL, stopRecoveryArgs(b)...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return decodeGrantEffect(ctx, rows)
}
