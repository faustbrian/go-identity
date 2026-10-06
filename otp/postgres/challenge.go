package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/otp"
	"github.com/jackc/pgx/v5"
)

// These private bridges will borrow only coordinator-owned phase handles.
// They cannot be injected through public configuration or acquire transactions.
// The native participant must first resolve command replay, current primary flow
// authority and shared lockout; then lock this row before any code comparison.
// No standalone lookup/check API is exposed while that composition is unfinished.
type challengeRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}
type challengeQuery func(context.Context, string, ...any) (challengeRows, error)
type challengeExec func(context.Context, string, ...any) (int64, error)

type lockedChallenge struct {
	challenge          otp.Challenge
	schema, tenant, id string
	keyVersion         uint32
	scopeDigest        [32]byte
}

// loadChallenge reconstructs the frozen primary snapshot from an authenticated
// original submission. A keyed full-scope selector prevents a foreign scope or
// retained alternate key from borrowing another row's counters. It deliberately
// does not compare codes, authorize a flow, claim a result or renew validity.
// The caller retains the row lock in the same owning coordinator transaction.
func (c *AttemptCodec) loadChallenge(ctx context.Context, query challengeQuery, schema string, a otp.AttemptCommand, version uint32) (lockedChallenge, error) {
	bad := func(err error) (lockedChallenge, error) { return lockedChallenge{}, err }
	if ctx == nil || query == nil || c == nil || c.crypto == nil || !validSchema(schema) {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	b, err := a.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	i, ok := c.issuers[b.FingerprintKeyVersion]
	if !ok {
		return bad(ErrInvalidCommand)
	}
	r, err := i.SealForCommand(a)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	plan, err := c.recordPlan(r, version)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	continuation, err := b.Continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	scope := continuation.Scope
	quoted := pgx.Identifier{schema}.Sanitize()
	rows, err := query(ctx, `SELECT e.subject_id,e.purpose,e.policy_version::text,e.scope_generation::text,
 e.code_digest,e.alphabet,e.code_length,e.ttl_us,e.resend_interval_us,e.maximum_sends,e.attempt_limit,e.replacement,
 e.checks_enabled,e.check_limit,e.lockout_us,e.issued_at,e.expires_at,e.state,e.version::text,e.used_attempts,e.failed_attempts,e.checks
 FROM `+quoted+`.challenges e WHERE e.tenant_id=$1 AND e.challenge_id=$2 AND e.digest_key_version=$3 AND e.scope_digest=$4
 AND EXISTS(SELECT 1 FROM identity.commands j WHERE j.command_id=e.issue_command_id AND j.tenant_id=e.tenant_id
 AND j.purpose=e.issue_command_purpose AND j.state='committed' AND j.terminal_class='committed') FOR UPDATE OF e`, scope.TenantID, scope.ChallengeID, int64(version), plan.ScopeDigest[:])
	if err != nil {
		return bad(challengeFailure(ctx))
	}
	if rows == nil {
		return bad(ErrUnavailable)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return bad(challengeFailure(ctx))
		}
		return bad(ErrInvalidCommand)
	}
	var subject, purpose, policy, generation, alphabet, replacement, state, rowVersion string
	var digest []byte
	var length, sends, attempts, checkLimit, used, failed, checks int64
	var ttl, resend, lockout int64
	var enabled bool
	var issuedAt, expiresAt time.Time
	if rows.Scan(&subject, &purpose, &policy, &generation, &digest, &alphabet, &length, &ttl, &resend, &sends, &attempts, &replacement, &enabled, &checkLimit, &lockout, &issuedAt, &expiresAt, &state, &rowVersion, &used, &failed, &checks) != nil || rows.Next() || rows.Err() != nil {
		return bad(challengeFailure(ctx))
	}
	// Independently bound every conversion even when installed SQL constraints
	// already enforce it: incompatible/malformed storage must never wrap into a
	// valid policy. Reuse core constructors instead of inventing policy defaults.
	if subject != scope.SubjectID || purpose != string(scope.Purpose) || policy != strconv.FormatUint(scope.PolicyVersion, 10) || generation != strconv.FormatUint(scope.Generation, 10) || len(digest) != 32 || length < 4 || length > 128 || ttl < 30000000 || ttl > 600000000 || resend < 30000000 || resend > 600000000 || sends < 1 || sends > 10 || attempts < 1 || attempts > 10 || checkLimit < 0 || checkLimit > 10 || lockout < 1 || lockout > 86400000000 || used < 0 || used > 10 || failed < 0 || failed > 10 || checks < 0 || checks > 10 {
		return bad(ErrUnavailable)
	}
	p := otp.CodeProfileSpec{Purpose: scope.Purpose, Alphabet: alphabet, Length: int(length), TTL: time.Duration(ttl) * time.Microsecond, ResendInterval: time.Duration(resend) * time.Microsecond, MaximumSends: uint32(sends), Attempts: uint32(attempts)}
	switch replacement {
	case "replace":
		p.Replacement = otp.ReplacePrevious
	case "retain":
		p.Replacement = otp.RetainPrevious
	default:
		return bad(ErrUnavailable)
	}
	profile, err := otp.NewCodeProfile(p)
	if err != nil {
		return bad(ErrUnavailable)
	}
	issuedPolicy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: enabled, MaximumChecks: uint32(checkLimit), LockoutAfter: time.Duration(lockout) * time.Microsecond})
	if err != nil {
		return bad(ErrUnavailable)
	}
	ver, err := strconv.ParseUint(rowVersion, 10, 64)
	if err != nil || strconv.FormatUint(ver, 10) != rowVersion {
		return bad(ErrUnavailable)
	}
	snapshot := otp.ChallengeSpec{Continuation: b.Continuation, Policy: issuedPolicy, Digest: otp.StoredCodeDigest{KeyVersion: version, Value: [32]byte(digest)}, IssuedAt: issuedAt, ExpiresAt: expiresAt, State: challengeState(state), Version: ver, UsedAttempts: uint32(used), FailedAttempts: uint32(failed), Checks: uint32(checks)}
	challenge, err := otp.NewChallenge(snapshot)
	if err != nil {
		return bad(ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return lockedChallenge{challenge: challenge, schema: quoted, tenant: scope.TenantID, id: scope.ChallengeID, keyVersion: version, scopeDigest: plan.ScopeDigest}, nil
}

func challengeState(state string) otp.ChallengeState {
	switch state {
	case "issued":
		return otp.ChallengeIssued
	case "reserved":
		return otp.ChallengeReserved
	case "finalized":
		return otp.ChallengeFinalized
	case "released":
		return otp.ChallengeReleased
	case "expired":
		return otp.ChallengeExpired
	case "revoked":
		return otp.ChallengeRevoked
	case "exhausted":
		return otp.ChallengeExhausted
	}
	return 0
}
func challengeFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

// persistCount applies only a new core-generated denial/check/expiry proposal
// to the exact locked issued row. Correct consumption has a different ownership
// CAS and is rejected here. The native owner MUST write required shared lockout,
// stable command result and audit in this same transaction before committing;
// this helper neither commits nor establishes those absent obligations.
func persistCount(ctx context.Context, exec challengeExec, row lockedChallenge, d otp.AttemptDecision, now time.Time) error {
	if ctx == nil || exec == nil || row.schema == "" || now.IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 || now.Nanosecond()%1000 != 0 {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := row.challenge.Bindings()
	if err != nil || s.State != otp.ChallengeIssued || s.Version == ^uint64(0) || d.Version != s.Version+1 {
		return ErrInvalidCommand
	}
	p, _, _ := s.Policy.Bindings()
	terminal := false
	state := "issued"
	if d.Outcome == otp.AttemptExpired {
		if d.State != otp.ChallengeExpired || now.Before(s.ExpiresAt) || d.UsedAttempts != s.UsedAttempts || d.FailedAttempts != s.FailedAttempts || d.Checks != s.Checks || d.LockoutAfter != 0 {
			return ErrInvalidCommand
		}
		terminal, state = true, "expired"
	} else {
		if d.Outcome != otp.AttemptDenied && d.Outcome != otp.AttemptChecked && d.Outcome != otp.AttemptExhausted || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || d.UsedAttempts != s.UsedAttempts+1 || d.UsedAttempts > p.Attempts || d.FailedAttempts < s.FailedAttempts || d.FailedAttempts > s.FailedAttempts+1 || d.Checks < s.Checks || d.Checks > s.Checks+1 || d.FailedAttempts == s.FailedAttempts && d.Checks == s.Checks {
			return ErrInvalidCommand
		}
		if d.UsedAttempts == p.Attempts {
			terminal, state = true, "exhausted"
			if d.State != otp.ChallengeExhausted {
				return ErrInvalidCommand
			}
		} else if d.State != otp.ChallengeIssued {
			return ErrInvalidCommand
		}
	}
	// Exclusive primary expiry is checked again at the write, after any wait.
	// A delayed update cannot spend allowance using an earlier positive clock.
	count, err := exec(ctx, `UPDATE `+row.schema+`.challenges SET state=$6,version=$7::numeric,used_attempts=$8,failed_attempts=$9,checks=$10,
 terminal_at=CASE WHEN $11 THEN $12::timestamptz ELSE NULL END
 WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4 AND version=$5::numeric AND state='issued'
 AND issued_at<=clock_timestamp() AND (($6='expired' AND expires_at<=clock_timestamp()) OR ($6<>'expired' AND expires_at>clock_timestamp()))`, row.tenant, row.id, int64(row.keyVersion), row.scopeDigest[:], strconv.FormatUint(s.Version, 10), state, strconv.FormatUint(d.Version, 10), int64(d.UsedAttempts), int64(d.FailedAttempts), int64(d.Checks), terminal, now)
	if err != nil {
		return challengeFailure(ctx)
	}
	if count != 1 {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
