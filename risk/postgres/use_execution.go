package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.RiskExecutionContributor = (*Repository)(nil)

// CheckRiskEvidence authenticates original phase-specific phone scope under
// current policy/provider custody and locks the exact reserved issued row. It
// requires the actual original durable counter attempt and current allowance
// inside the same sole coordinator transaction. Original check/issuance/expiry
// never renew. Missing, terminal, foreign, stale or unavailable authority denies.
// Native phone/factor/current-user authorization remains the feature owner's
// responsibility. No callback, provider, private transaction or handle retention
// occurs; independent invocations are concurrent-safe, each Work is serial-use.
func (r *Repository) CheckRiskEvidence(ctx context.Context, w identitypostgres.RiskApplyWork) error {
	_, err := r.checkRiskUse(ctx, w)
	return err
}

// FinalizeRiskEvidence repeats the current original-row/counter checks and
// CASes the exact reserved command/fingerprint/generation to finalized in the
// protected mutation transaction, with exclusive database-time expiry. Zero
// affected rows requires rollback of every provisional effect, not release.
// It never issues, renews, retries, opens a private transaction or invokes a
// provider/caller callback. Unknown outcomes retain reserved custody and use
// existing coordinator recovery; expiry alone grants no release or reuse.
func (r *Repository) FinalizeRiskEvidence(ctx context.Context, w identitypostgres.RiskFinalizeWork) error {
	args, err := r.checkRiskUse(ctx, w)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE `+r.schema+`.issued_evidence e SET state='finalized' WHERE `+reservedEvidencePredicate+` AND expires_at>clock_timestamp() AND reserved_at<=clock_timestamp()`, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Only the sealed, owner-bound coordinator handles implement this private
// phase-independent view. Neither callback nor transaction authority is added.
type riskCurrentWork interface {
	Binding(identitypostgres.RiskReservationContributor) (identitypostgres.RiskReservationBinding, error)
	NativeCommand(identitypostgres.RiskReservationContributor) (identity.Command, error)
	Query(context.Context, string, ...any) (*identitypostgres.WorkRows, error)
	DatabaseTime(context.Context) (time.Time, error)
}

func (r *Repository) checkRiskUse(ctx context.Context, w riskCurrentWork) ([]any, error) {
	if ctx == nil || r == nil || r.schema == "" || r.useIssuer == nil || r.useCounters == nil {
		return nil, risk.ErrInvalidEvidenceExecution
	}
	b, err := w.Binding(r)
	if err != nil {
		return nil, err
	}
	command, err := w.NativeCommand(r)
	if err != nil {
		return nil, err
	}
	original, spec, err := r.restoreUseCommand(command, b.Plan, useCheckTime(b.Plan.CheckedAt))
	if err != nil || spec.Binding != b.Command || b.PreviousGeneration != 0 || b.Generation == 0 || b.Fingerprint == ([32]byte{}) {
		return nil, identity.ConflictError{}
	}
	claim, err := r.restoreUse(b)
	if err != nil {
		return nil, identity.ConflictError{}
	}
	current := b
	current.PreviousGeneration = b.Generation
	args := reservedEvidenceArgs(current)
	rows, err := w.Query(ctx, `SELECT e.reserved_at FROM `+r.schema+`.issued_evidence e WHERE `+reservedEvidencePredicate+` FOR UPDATE OF e`, args...)
	if err != nil {
		return nil, err
	}
	var reservedAt time.Time
	matched := rows.Next() && rows.Scan(&reservedAt) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched {
		return nil, identity.ConflictError{}
	}
	now, err := r.checkUseCounters(ctx, w, original, claim.Prepared())
	if err != nil {
		return nil, err
	}
	if now.Before(reservedAt) || claim.Validate(now) != nil {
		return nil, identity.ConflictError{}
	}
	return args, nil
}
