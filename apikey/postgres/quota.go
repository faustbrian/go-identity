package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The key/configuration locks are already held by the sole verifier participant.
// This state and the original command effect commit or roll back in that Work.
// Numeric arithmetic is exact: interval microseconds are the denominator, so
// elapsed microseconds accrue integer numerator units without losing fractions.
func (p *verificationPhase) debitQuota(ctx context.Context, w kernel.Work, record apikey.Record) (*apikey.QuotaMetadata, bool, error) {
	policy := p.service.config().Configuration.Spec().TokenBucket
	at, err := w.DatabaseTime(ctx)
	at = at.UTC()
	if err != nil || policy.Validate() != nil || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || at != at.Truncate(time.Microsecond) {
		return nil, false, identity.UnavailableError{}
	}
	capacity := strconv.FormatUint(policy.Capacity, 10)
	period := strconv.FormatInt(policy.RefillInterval.Microseconds(), 10)
	args := []any{string(p.binding.TenantID), record.ConfigurationID, string(record.ID), capacity, period}
	if _, err := w.Exec(ctx, initializeQuotaSQL, append(args, at)...); err != nil {
		return nil, false, err
	}
	args = append(args, strconv.FormatUint(policy.RefillAmount, 10), strconv.FormatUint(p.request.DebitAmount, 10), at)
	rows, err := w.Query(ctx, debitQuotaSQL, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var debited bool
	var remaining int64
	if !rows.Next() || rows.Scan(&debited, &remaining) != nil || rows.Next() || rows.Err() != nil || remaining < 0 {
		return nil, false, identity.UnavailableError{}
	}
	metadata := &apikey.QuotaMetadata{TokenBucketPolicy: policy, Remaining: uint64(remaining), ObservedAt: at}
	if metadata.Validate() != nil {
		return nil, false, identity.UnavailableError{}
	}
	return metadata, debited, nil
}

const initializeQuotaSQL = `INSERT INTO identity_api_keys.quotas(tenant_id,configuration_id,key_id,capacity_units,balance,observed_at)
VALUES($1,$2,$3,$4::numeric*$5::numeric,$4::numeric*$5::numeric,$6)
ON CONFLICT(tenant_id,configuration_id,key_id) DO NOTHING`

// Matching immutable capacity and monotonic microsecond database time are
// mandatory; incompatible/corrupt state returns no row and rolls back the Work.
// The numeric(39,0) bound covers uint64 refill * the entire finite PG time range.
const debitQuotaSQL = `WITH locked AS MATERIALIZED (
 SELECT balance,observed_at FROM identity_api_keys.quotas
 WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3
 AND capacity_units=$4::numeric*$5::numeric AND observed_at<=$8::timestamptz
 FOR UPDATE
), allowance AS MATERIALIZED (
 SELECT LEAST($4::numeric*$5::numeric,balance+EXTRACT(EPOCH FROM ($8::timestamptz-observed_at))*1000000*$6::numeric) AS available
 FROM locked
), changed AS (
 UPDATE identity_api_keys.quotas q SET
 balance=a.available-CASE WHEN a.available >= $7::numeric*$5::numeric THEN $7::numeric*$5::numeric ELSE 0 END,
 observed_at=$8::timestamptz
 FROM allowance a WHERE q.tenant_id=$1 AND q.configuration_id=$2 AND q.key_id=$3
 RETURNING a.available >= $7::numeric*$5::numeric AS debited,FLOOR(q.balance/$5::numeric)::bigint AS remaining
)
SELECT debited,remaining FROM changed`
