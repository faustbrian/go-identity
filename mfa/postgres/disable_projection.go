package mfapostgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Capture the committed successor's display state under the coordinator's
// existing tenant serialization. A later pool read would observe another
// command, and the public list cannot authenticate a deliberately revoked
// source session. Revoked history and expired pending records are not remaining
// factors. Never read secret/replay material or disclose a partial inventory.
func (p *factorUpdatePhase) readDisableRemaining(ctx context.Context, w kernel.Work) error {
	b := p.input.Binding
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT factor_id,state,label,created_at,row_version::text FROM `+p.state.factorTable()+` WHERE tenant_id=$1 AND user_id=$2 AND state<>3 AND (state<>1 OR enrollment_expires_at>$3) ORDER BY factor_id LIMIT 101`, string(b.TenantID), string(b.UserID), now)
	if err != nil {
		return err
	}
	defer rows.Close()
	factors := make([]mfa.FactorProjection, 0, 8)
	for rows.Next() {
		var factor mfa.FactorProjection
		var id, version string
		var state int16
		if err := rows.Scan(&id, &state, &factor.Label, &factor.CreatedAt, &version); err != nil {
			return identity.UnavailableError{}
		}
		v, err := strconv.ParseUint(version, 10, 64)
		if err != nil || version != strconv.FormatUint(v, 10) || state != int16(mfa.FactorPending) || id == string(p.targetID()) || len(factors) == 100 {
			return identity.UnavailableError{}
		}
		factor.ID, factor.Method, factor.State, factor.Version = mfa.FactorID(id), p.state.method(), mfa.FactorPending, v
		factors = append(factors, factor)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if p.disable.Target == mfa.AllFactors && len(factors) != 0 || (mfa.ListResult{Factors: factors}).ValidateAt(now) != nil {
		return identity.UnavailableError{}
	}
	p.remaining = factors
	return nil
}
