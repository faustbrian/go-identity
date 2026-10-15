package mfapostgres

import (
	"context"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

type recoveryStore struct {
	sql  totpAttemptSQL
	read func(context.Context, identity.CommandBinding, kernel.MFACompletionPlan) ([]recoveryCodeRow, error)
}

func recoveryWorkStore(query func(context.Context, string, ...any) (*kernel.WorkRows, error), exec func(context.Context, string, ...any) (int64, error)) recoveryStore {
	return recoveryStore{sql: totpAttemptSQL{exec: exec, query: func(ctx context.Context, statement string, args []any, dest ...any) error {
		rows, err := query(ctx, statement, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		if rows.Next() {
			return invalidAuthority()
		}
		return rows.Err()
	}}, read: func(ctx context.Context, b identity.CommandBinding, p kernel.MFACompletionPlan) ([]recoveryCodeRow, error) {
		rows, err := query(ctx, recoveryRowsSQL, string(b.TenantID), string(p.UserID))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var result []recoveryCodeRow
		for rows.Next() {
			if len(result) == 4096 {
				return nil, identity.UnavailableError{}
			}
			var r recoveryCodeRow
			var epoch, version, enrollment string
			var key int64
			var count, index int16
			var digest []byte
			err := rows.Scan(&r.set.SetID, &r.set.FactorID, &epoch, &version, &key, &count, &index, &digest, &r.consumed, &enrollment)
			if err != nil {
				clear(digest)
				return nil, err
			}
			r.set.TenantID, r.set.UserID = b.TenantID, p.UserID
			r.set.SetVersion, err = strconv.ParseUint(epoch, 10, 64)
			if err != nil {
				clear(digest)
				return nil, invalidAuthority()
			}
			r.set.RowVersion, err = strconv.ParseUint(version, 10, 64)
			if err != nil || r.set.SetVersion == 0 || r.set.RowVersion == 0 || key < 1 || key > 4294967295 || count < 1 || count > 64 || index < 0 || index >= count || len(digest) != 32 {
				clear(digest)
				return nil, invalidAuthority()
			}
			r.set.FactorEnrollmentVersion, err = strconv.ParseUint(enrollment, 10, 64)
			if err != nil || r.set.FactorEnrollmentVersion == 0 {
				clear(digest)
				return nil, invalidAuthority()
			}
			r.set.KeyVersion, r.set.CodeCount, r.index = uint32(key), uint32(count), uint32(index)
			copy(r.digest[:], digest)
			clear(digest)
			result = append(result, r)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return result, nil
	}}
}

// Shared authority/continuation locks precede deterministic factor/set locks.
// Every code writer holds those same owner locks; burning additionally locks
// the selected code row. Read consumed rows too and retain incomplete sets via
// LEFT JOIN: corruption must fail closed, not disappear as ordinary bad input.
const recoveryRowsSQL = `SELECT r.set_id,r.factor_id,r.set_version::text,r.row_version::text,r.key_version,r.code_count,c.code_index,c.digest,(c.consumed_at IS NOT NULL),t.enrollment_version::text
FROM identity_mfa.recovery_sets r
JOIN identity_mfa.totp_factors t ON t.tenant_id=r.tenant_id AND t.user_id=r.user_id AND t.factor_id=r.factor_id
LEFT JOIN identity_mfa.recovery_codes c ON c.tenant_id=r.tenant_id AND c.set_id=r.set_id
WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.state=2 AND t.state=2 AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL
ORDER BY r.set_id,c.code_index LIMIT 4097 FOR UPDATE OF t,r`

func validateRecoveryRows(rows []recoveryCodeRow) error {
	sets := 0
	factors := make(map[string]bool)
	for offset := 0; offset < len(rows); {
		m := rows[offset].set
		if m.CodeCount < 1 || m.CodeCount > 64 || m.RowVersion == 0 || m.FactorEnrollmentVersion == 0 || factors[m.FactorID] || sets == 64 || int(m.CodeCount) > len(rows)-offset {
			return identity.UnavailableError{}
		}
		if _, err := recoveryCodeBinding(m); err != nil {
			return err
		}
		factors[m.FactorID], sets = true, sets+1
		for index := uint32(0); index < m.CodeCount; index++ {
			row := rows[offset+int(index)]
			if row.set != m || row.index != index {
				return identity.UnavailableError{}
			}
		}
		offset += int(m.CodeCount)
	}
	return nil
}

func lockRecovery(ctx context.Context, store recoveryStore, b kernel.MFARecoveryAttemptBinding, keys RecoveryVerificationKeys, code auth.RecoveryCode) (mfa.PartialAuthContinuation, time.Time, recoveryCodeRow, bool, error) {
	if ctx == nil || keys.key == nil || b.Command.OperationID != "identity.mfa.recovery-use" {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, invalidAuthority()
	}
	c, now, err := lockMFAAttemptContinuation(ctx, store.sql, kernel.MFATOTPAttemptBinding{Command: b.Command, Plan: b.Plan, Fingerprint: b.Fingerprint, Generation: b.Generation}, "recovery-code")
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, err
	}
	rows, err := store.read(ctx, b.Command, b.Plan)
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, attemptStoreError(ctx, err)
	}
	defer func() {
		for i := range rows {
			clear(rows[i].digest[:])
		}
	}()
	if err := validateRecoveryRows(rows); err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, err
	}
	index, found, err := compareRecoveryCodes(ctx, keys, code, rows)
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, err
	}
	// Refresh database time, never proof freshness, after the bounded scan.
	if err := store.sql.query(ctx, `SELECT clock_timestamp()`, nil, &now); err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, attemptStoreError(ctx, err)
	}
	if c.RequirePending(now) != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, recoveryCodeRow{}, false, identity.ForbiddenError{}
	}
	if !found {
		return c, now.UTC(), recoveryCodeRow{}, false, nil
	}
	return c, now.UTC(), rows[index], true, nil
}
