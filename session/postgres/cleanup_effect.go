package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

const maximumCleanupLag = 8760 * time.Hour

func (r *Repository) validateCleanupPlan(c identity.Command, p kernel.CommandPlan) error {
	_, limit, err := nativeCleanup(c)
	if err != nil || r == nil || r.cleanupBatch == 0 || limit > r.cleanupBatch || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != cleanupOperation() || p.SubjectType != "session_cleanup" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.expired.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.expire" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

// Materializing the indexed candidate set before locks bounds rows considered,
// not only successful deletions. The locking join rechecks current expiry after
// refresh and skips busy rows. Delete rechecks again and the existing rotation
// trigger terminally retires every deleted digest in this same Work.
func (r *Repository) applyCleanup(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	b, limit, err := nativeCleanup(command)
	if err != nil || ctx == nil || r == nil || r.cleanupBatch == 0 || limit > r.cleanupBatch {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bound, feature, transition, err := w.FeatureScope(r)
	if err != nil || bound != b || feature.Operation != cleanupOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || !sessionReadTime(now) {
		return identity.FeatureReceipt{}, session.ErrUnavailable
	}
	cutoff := now.UTC().Format(storedTimeLayout)
	sql := `WITH candidates AS MATERIALIZED (SELECT session_id FROM ` + r.schema + `.sessions WHERE tenant_id=$1 AND user_id=$2 AND expires_at<=$3 ORDER BY expires_at,session_id LIMIT $4), locked AS MATERIALIZED (SELECT s.session_id FROM ` + r.schema + `.sessions s JOIN candidates c USING(session_id) JOIN ` + r.schema + `.token_claims t ON t.tenant_id=s.tenant_id AND t.session_id=s.session_id AND t.digest_version=s.digest_version AND t.digest=s.digest WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.expires_at<=$3 ORDER BY s.session_id FOR UPDATE OF s SKIP LOCKED), deleted AS (DELETE FROM ` + r.schema + `.sessions s USING locked l WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.session_id=l.session_id AND s.expires_at<=$3 RETURNING s.session_id) SELECT count(*) FROM deleted`
	rows, err := w.Query(ctx, sql, string(b.TenantID), string(b.UserID), cutoff, int64(limit))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var count int64
	err = readSessionAdmission(rows, &count)
	rows.Close()
	if err != nil || count < 0 || count > int64(limit) {
		return identity.FeatureReceipt{}, session.ErrUnavailable
	}
	rows, err = w.Query(ctx, `SELECT expires_at FROM `+r.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND expires_at<=$3 ORDER BY expires_at,session_id LIMIT 1`, string(b.TenantID), string(b.UserID), cutoff)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var oldest string
	if rows.Next() {
		err = rows.Scan(&oldest)
		if rows.Next() {
			err = session.ErrUnavailable
		}
	}
	if rows.Err() != nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	lag := time.Duration(0)
	if oldest != "" {
		expiry, err := time.Parse(storedTimeLayout, oldest)
		if err != nil || expiry.UTC().Format(storedTimeLayout) != oldest || expiry.After(now) {
			return identity.FeatureReceipt{}, session.ErrUnavailable
		}
		lag = now.Sub(expiry)
		if lag > maximumCleanupLag {
			lag = maximumCleanupLag
		}
	}
	stored := cleanupEvidence{limit: limit, count: uint32(count), observed: now.UTC(), lag: lag}
	id, digest := cleanupBindingDigest(b, stored)
	n, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.cleanup_results(tenant_id,command_id,purpose,user_id,considered_limit,deleted_count,observed_at,remaining_lag_ns,binding_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, string(b.TenantID), id, b.OperationID, string(b.UserID), int64(limit), count, cutoff, int64(lag), digest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: cleanupOperation()}, nil
}

type cleanupEvidence struct {
	limit, count uint32
	observed     time.Time
	lag          time.Duration
}

func cleanupBindingDigest(b identity.CommandBinding, e cleanupEvidence) ([]byte, [32]byte) {
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	data, _ := json.Marshal(struct {
		Binding      identity.CommandBinding
		Limit, Count uint32
		Observed     string
		Lag          int64
	}{b, e.limit, e.count, e.observed.UTC().Format(storedTimeLayout), int64(e.lag)})
	return id, sha256.Sum256(append([]byte("identity-session-cleanup-result-v1\x00"), data...))
}

func (r *Repository) cleanupSelect() string {
	return `SELECT user_id,purpose,considered_limit,deleted_count,observed_at,remaining_lag_ns,binding_digest FROM ` + r.schema + `.cleanup_results WHERE tenant_id=$1 AND command_id=$2`
}

func scanCleanup(row rotationScanner, b identity.CommandBinding) (cleanupEvidence, error) {
	var out cleanupEvidence
	var user, purpose, observed string
	var limit, count, lag int64
	var digest []byte
	if err := row.Scan(&user, &purpose, &limit, &count, &observed, &lag, &digest); err != nil {
		return out, session.ErrUnavailable
	}
	stamp, err := time.Parse(storedTimeLayout, observed)
	if err != nil || !sessionReadTime(stamp) || stamp.UTC().Format(storedTimeLayout) != observed || user != string(b.UserID) || purpose != cleanupOperation().OperationID || limit < 1 || limit > 10000 || count < 0 || count > limit || lag < 0 || lag > int64(maximumCleanupLag) {
		return out, session.ErrUnavailable
	}
	out = cleanupEvidence{uint32(limit), uint32(count), stamp, time.Duration(lag)}
	_, expected := cleanupBindingDigest(b, out)
	if subtle.ConstantTimeCompare(digest, expected[:]) != 1 {
		return cleanupEvidence{}, session.ErrUnavailable
	}
	return out, nil
}

func (s *CleanupService) cleanupResult(ctx context.Context, result identity.CommandResult, err error) (CleanupResult, error) {
	out := CleanupResult{Command: result}
	if result.Binding.CommandID == "" {
		return out, err
	}
	if result.Feature == nil || result.Feature.Operation != cleanupOperation() {
		return CleanupResult{}, session.ErrUnavailable
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	id, _ := cleanupBindingDigest(result.Binding, cleanupEvidence{})
	rows, err := s.owned.native.pool.Raw().Query(ctx, s.owned.native.cleanupSelect(), string(result.Binding.TenantID), id)
	if err != nil {
		return out, readError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return out, session.ErrUnavailable
	}
	evidence, err := scanCleanup(rows, result.Binding)
	if err != nil || rows.Next() || rows.Err() != nil {
		return out, session.ErrUnavailable
	}
	if ctx.Err() != nil {
		return out, readError(ctx, ctx.Err())
	}
	out.Deleted, out.RemainingLag, out.ObservedAt = evidence.count, evidence.lag, evidence.observed
	return out, nil
}

func (r *Repository) recoverCleanup(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || feature.Operation != cleanupOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, _ := cleanupBindingDigest(b, cleanupEvidence{})
	rows, err := w.Query(ctx, r.cleanupSelect(), string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if _, err := scanCleanup(rows, b); err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
