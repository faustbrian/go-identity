package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Native writers seal acknowledged facts in their owning transaction, never a
// caller projection or an unauthenticated legacy record. Distinct domains and
// length framing bind every original row, dimension, alias and snapshot.
func (s *velocityJournal) sealVelocity(ctx context.Context, tx pgx.Tx, sequence int64) error {
	expected, _, err := s.velocitySeal(ctx, tx, sequence)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.velocity_attempts SET replay_seal=$2 WHERE sequence=$1`, sequence, expected); err != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (s *velocityJournal) checkVelocitySeal(ctx context.Context, tx pgx.Tx, sequence int64) error {
	expected, stored, err := s.velocitySeal(ctx, tx, sequence)
	if err != nil {
		return err
	}
	// Missing authentication is not a legacy bypass. Preserve those rows for
	// attributable recovery; do not bless their facts or synthesize a seal.
	if len(stored) != 32 || !hmac.Equal(expected, stored) {
		return identity.UnavailableError{}
	}
	return nil
}

func (s *velocityJournal) velocitySeal(ctx context.Context, tx pgx.Tx, sequence int64) ([]byte, []byte, error) {
	var tenant, operation, phase, policy, window, limit, outcome string
	var namespace, attempt, fingerprint, stored []byte
	var prepared, recorded time.Time
	err := tx.QueryRow(ctx, `SELECT tenant_id,namespace_digest,operation,phase,policy_version::text,attempt_digest,counter_fingerprint,prepared_at,recorded_at,window_us::text,attempt_limit::text,outcome,replay_seal FROM `+s.schema+`.velocity_attempts WHERE sequence=$1`, sequence).Scan(&tenant, &namespace, &operation, &phase, &policy, &attempt, &fingerprint, &prepared, &recorded, &window, &limit, &outcome, &stored)
	if err != nil {
		return nil, nil, identity.UnavailableError{}
	}
	fields := []string{strconv.FormatInt(sequence, 10), tenant, hex.EncodeToString(namespace), operation, phase, policy, hex.EncodeToString(attempt), hex.EncodeToString(fingerprint), velocitySealTime(prepared), velocitySealTime(recorded), window, limit, outcome}
	// Each group carries an independent label and count. Sorting is invariant
	// under SQL row order; limits bound hostile/partial native journal history.
	queries := []struct {
		label, query     string
		columns, maximum int
	}{
		{"targets", `SELECT dimension,phase,window_us::text FROM ` + s.schema + `.velocity_targets WHERE sequence=$1 ORDER BY dimension LIMIT 5`, 3, 4},
		{"aliases", `SELECT dimension,key_rank::text,key_version::text,key_id FROM ` + s.schema + `.velocity_aliases WHERE sequence=$1 ORDER BY dimension,key_rank LIMIT 17`, 4, 16},
		{"snapshots", `SELECT dimension,value::text,observed_at,started_at,expires_at FROM ` + s.schema + `.velocity_snapshots WHERE sequence=$1 ORDER BY dimension LIMIT 5`, 5, 4},
	}
	for _, q := range queries {
		rows, err := tx.Query(ctx, q.query, sequence)
		if err != nil {
			return nil, nil, identity.UnavailableError{}
		}
		var values []string
		count := 0
		for rows.Next() {
			count++
			if count > q.maximum {
				rows.Close()
				return nil, nil, identity.UnavailableError{}
			}
			if q.label == "snapshots" {
				var dimension, value string
				var observed, started, expires time.Time
				if err := rows.Scan(&dimension, &value, &observed, &started, &expires); err != nil {
					rows.Close()
					return nil, nil, identity.UnavailableError{}
				}
				values = append(values, dimension, value, velocitySealTime(observed), velocitySealTime(started), velocitySealTime(expires))
			} else {
				v := make([]string, q.columns)
				dest := make([]any, q.columns)
				for i := range v {
					dest[i] = &v[i]
				}
				if err := rows.Scan(dest...); err != nil {
					rows.Close()
					return nil, nil, identity.UnavailableError{}
				}
				values = append(values, v...)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, identity.UnavailableError{}
		}
		fields = append(fields, q.label, strconv.Itoa(count))
		fields = append(fields, values...)
	}
	return velocityMAC(s.key, "identity-risk-velocity-record-v1", fields...), stored, nil
}

// Unix microseconds are independent of database/client timezone and text style.
func velocitySealTime(t time.Time) string { return strconv.FormatInt(t.UnixMicro(), 10) }
