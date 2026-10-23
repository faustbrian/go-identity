package anonymouspostgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// CleanupExpired selects at most Limit indexed expired subjects, then executes
// their independently atomic owner commands. Selection holds no locks across
// callbacks: original version/expiry/hold fences arbitrate upgrade/deletion
// races. It stops on unknown/unavailable/cancellation, preserving attempted
// original queries; policy-denied items remain pending and do not starve later
// pages when the caller advances Next. No automatic retry or scheduler runs.
func (s *CleanupService) CleanupExpired(ctx context.Context, r CleanupRequest) (out CleanupResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Limit == 0 || r.Limit > s.config().MaximumBatch {
		return out, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.RunID)); err != nil {
		return out, anonymous.ErrInvalidInput
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().GlobalAuthorityID, TenantID: r.TenantID}
	if query.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	if r.After != nil {
		if !readInstant(r.After.ExpiresAt) || r.After.ExpiresAt.Nanosecond()%1000 != 0 || (anonymous.SubjectQuery{TenantID: r.TenantID, UserID: r.After.UserID}).Validate() != nil {
			return out, anonymous.ErrInvalidInput
		}
		cursor := *r.After
		r.After = &cursor
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out.LagKnown = false
			err = identity.UnavailableError{}
		}
		if err != nil {
			err = signinPublicError(ctx, err)
		}
	}()
	if err = s.allow(ctx, r.TenantID, "expired"); err != nil {
		return out, err
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, query)
	if err != nil {
		return out, err
	}
	if !directory.Enabled {
		return out, identity.ForbiddenError{}
	}
	candidates, at, err := s.expiredPage(ctx, r)
	if err != nil {
		return out, err
	}
	out.ObservedAt = at
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		item, itemErr := s.CleanupSubject(ctx, CleanupSubjectRequest{TenantID: r.TenantID, UserID: candidate.UserID, RunID: r.RunID})
		item.Error = itemErr
		out.Items = append(out.Items, item)
		position := candidate
		out.Next = &position
		if item.Outcome == identity.CommitOutcomeUnknown || item.Outcome == identity.CommitOutcomeInProgress {
			if itemErr == nil {
				itemErr = identity.UnavailableError{}
			}
			return out, itemErr
		}
		if itemErr != nil && !cleanupDeferred(itemErr) {
			return out, itemErr
		}
	}
	if err := s.remainingCleanupLag(ctx, r.TenantID, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (s *CleanupService) expiredPage(ctx context.Context, r CleanupRequest) ([]CleanupCursor, time.Time, error) {
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nil, time.Time{}, identity.UnavailableError{}
	}
	if !readInstant(at) {
		return nil, time.Time{}, identity.UnavailableError{}
	}
	// Reuse subjects(tenant_id,expires_at,user_id) WHERE state=1. A bound
	// authoritative cutoff makes the range indexable; no function wraps indexed
	// columns, OFFSET scan or selection transaction survives into policy work.
	sql := `SELECT user_id,expires_at FROM ` + s.repository.schema + `.subjects WHERE tenant_id=$1 AND state=1 AND expires_at<=$2`
	args := []any{string(r.TenantID), at}
	if r.After != nil {
		sql += ` AND (expires_at,user_id)>($3,$4)`
		args = append(args, r.After.ExpiresAt, string(r.After.UserID))
	}
	args = append(args, int64(r.Limit))
	sql += ` ORDER BY expires_at,user_id LIMIT $` + strconv.Itoa(len(args))
	rows, err := s.pool.Raw().Query(ctx, sql, args...)
	if err != nil {
		return nil, time.Time{}, identity.UnavailableError{}
	}
	defer rows.Close()
	var candidates []CleanupCursor
	for rows.Next() {
		if uint32(len(candidates)) >= r.Limit {
			return nil, time.Time{}, identity.UnavailableError{}
		}
		var id string
		var expiry time.Time
		if err := rows.Scan(&id, &expiry); err != nil {
			return nil, time.Time{}, identity.UnavailableError{}
		}
		if (anonymous.SubjectQuery{TenantID: r.TenantID, UserID: identity.UserID(id)}).Validate() != nil || !readInstant(expiry) || expiry.After(at) {
			return nil, time.Time{}, identity.UnavailableError{}
		}
		candidates = append(candidates, CleanupCursor{UserID: identity.UserID(id), ExpiresAt: expiry.UTC()})
	}
	if rows.Err() != nil || ctx.Err() != nil {
		return nil, time.Time{}, identity.UnavailableError{}
	}
	return candidates, at.UTC(), nil
}

func (s *CleanupService) remainingCleanupLag(ctx context.Context, tenant identity.TenantID, out *CleanupResult) error {
	var at time.Time
	var first *time.Time
	// The same partial index supplies the oldest remaining active lifecycle.
	// A future minimum means there is no expired backlog. Held and contended
	// subjects are intentionally included rather than reporting an empty queue.
	err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp(),(SELECT expires_at FROM `+s.repository.schema+`.subjects WHERE tenant_id=$1 AND state=1 ORDER BY expires_at,user_id LIMIT 1)`, string(tenant)).Scan(&at, &first)
	if err != nil || !readInstant(at) || first != nil && !readInstant(*first) {
		return identity.UnavailableError{}
	}
	var lag time.Duration
	if first != nil && first.Before(at) {
		lag = at.Sub(*first)
		if lag > 8760*time.Hour {
			lag = 8760 * time.Hour
		}
	}
	out.ObservedAt, out.RemainingLag, out.LagKnown = at.UTC(), lag, true
	return nil
}
