package postgres

import (
	"context"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const proxyDisablePairPK = `tenant_id=$1 AND source_command_id=$2`

func proxyDisablePairReadSQL(table string) string {
	return `SELECT cascade_id,generation,production_schema,production_deployment,preview_schema,preview_deployment,acknowledged_at
 FROM ` + table + ` WHERE ` + proxyDisablePairPK
}

func proxyDisablePairInsertSQL(table string) string {
	return `INSERT INTO ` + table + ` (tenant_id,source_command_id,cascade_id,generation,
 production_schema,production_deployment,preview_schema,preview_deployment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
}

func proxyDisablePairConfirmSQL(table string) string {
	return `UPDATE ` + table + ` SET acknowledged_at=greatest(clock_timestamp(),$9::timestamptz)
 WHERE ` + proxyDisablePairPK + ` AND cascade_id=$3 AND generation=$4 AND production_schema=$5
 AND production_deployment=$6 AND preview_schema=$7 AND preview_deployment=$8 AND acknowledged_at IS NULL
 RETURNING acknowledged_at`
}

func proxyDisablePairArgs(admission ProviderDisableAdmission, scope proxyDisablePairScope) []any {
	return []any{string(admission.Disable.Key.TenantID), string(admission.Disable.CommandID), string(admission.CascadeID),
		int64(admission.Generation), scope.productionSchema, scope.productionDeployment, scope.previewSchema, scope.previewDeployment}
}

func stageProxyDisablePair(ctx context.Context, tx pgx.Tx, table string, admission ProviderDisableAdmission, scope proxyDisablePairScope) error {
	written, err := tx.Exec(ctx, proxyDisablePairInsertSQL(table), proxyDisablePairArgs(admission, scope)...)
	if err != nil || written.RowsAffected() != 1 {
		return providerAuthorityFailure(ctx)
	}
	return nil
}

type proxyDisablePairReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readProxyDisablePair(ctx context.Context, reader proxyDisablePairReader, table string, admission ProviderDisableAdmission, scope proxyDisablePairScope) (time.Time, error) {
	var cascade string
	var generation int64
	var retained proxyDisablePairScope
	var at pgtype.Timestamptz
	err := reader.QueryRow(ctx, proxyDisablePairReadSQL(table), string(admission.Disable.Key.TenantID), string(admission.Disable.CommandID)).
		Scan(&cascade, &generation, &retained.productionSchema, &retained.productionDeployment, &retained.previewSchema, &retained.previewDeployment, &at)
	if errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
		return time.Time{}, identity.ForbiddenError{}
	}
	if err != nil || ctx.Err() != nil {
		return time.Time{}, providerAuthorityFailure(ctx)
	}
	if cascade != string(admission.CascadeID) || generation != int64(admission.Generation) || retained != scope {
		return time.Time{}, identity.ForbiddenError{}
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	if at.InfinityModifier != pgtype.Finite || at.Time.IsZero() || at.Time.Before(admission.AdmittedAt) {
		return time.Time{}, identity.UnavailableError{}
	}
	return at.Time.UTC(), nil
}

func confirmProxyDisablePair(ctx context.Context, pool *pgxpool.Pool, table string, admission ProviderDisableAdmission, scope proxyDisablePairScope) (time.Time, error) {
	// Both durable checkpoints were read before this transaction. Exhaustion is
	// sticky and the activated writer fences cannot admit an older origin.
	// Never hold a lock on the primary while reading either custody database.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return time.Time{}, providerAuthorityFailure(ctx)
	}
	defer rollbackProviderAuthority(tx)
	args := append(proxyDisablePairArgs(admission, scope), admission.AdmittedAt)
	var at time.Time
	err = tx.QueryRow(ctx, proxyDisablePairConfirmSQL(table), args...).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
		// An exact concurrent acknowledgement can win the one-row CAS.
		// Reread and accept only the original scope and its persisted result.
		at, err = readProxyDisablePair(ctx, tx, table, admission, scope)
		if err != nil {
			return time.Time{}, err
		}
		if at.IsZero() {
			return time.Time{}, identity.ConflictError{}
		}
		return at, nil
	}
	if err != nil || ctx.Err() != nil || at.IsZero() || at.Before(admission.AdmittedAt) {
		return time.Time{}, providerAuthorityFailure(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return time.Time{}, identity.UnavailableError{}
		}
		return time.Time{}, identity.UnknownCommitError{CommandID: admission.Disable.CommandID}
	}
	return at.UTC(), nil
}
