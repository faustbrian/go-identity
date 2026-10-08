package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// Native persistence borrows only the sole coordinator's phase. It owns no
// transaction, journal, policy callback, generation or delivery. Its caller
// must admit current original flow/risk and lock shared abuse rows first, then
// the send family. Any error requires rollback of the whole original Work.
// The caller must recheck authority/expiry after these additional lock waits.
func (p lockoutProfile) persistIssuance(ctx context.Context, query challengeQuery, exec challengeExec, codec *AttemptCodec, row lockedSendFamily, draft otp.Challenge, binding identity.CommandBinding, now time.Time) error {
	if ctx == nil || query == nil || exec == nil || codec == nil || codec.crypto == nil || !nativeTime(now) || row.schema == "" || row.version == 0 || row.version == ^uint64(0) {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := draft.Bindings()
	if err != nil {
		return ErrInvalidCommand
	}
	continuation, err := s.Continuation.Bindings()
	if err != nil {
		return ErrInvalidCommand
	}
	scope := continuation.Scope
	profile, checks, err := s.Policy.Bindings()
	command, valid := ownershipID(string(binding.CommandID))
	family, familyErr := p.sendIdentity(scope)
	if err != nil || !valid || familyErr != nil || family != row.digest || scope.TenantID != row.tenant || scope.Purpose != row.purpose || binding.TenantID != identity.TenantID(scope.TenantID) || string(binding.UserID) != scope.SubjectID || binding.OperationID != "identity.otp.send" || binding.RecordID != scope.ChallengeID || s.State != otp.ChallengeIssued || s.Version != 1 || s.UsedAttempts != 0 || s.FailedAttempts != 0 || s.Checks != 0 || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || profile.TTL%time.Microsecond != 0 || profile.ResendInterval%time.Microsecond != 0 {
		return ErrInvalidCommand
	}
	digestScope, err := s.Continuation.DigestScope()
	if err != nil {
		return ErrInvalidCommand
	}
	scopeDigest, err := codec.verifier.ScopeDigest(digestScope, s.Digest.KeyVersion)
	if err != nil {
		return ErrInvalidCommand
	}
	predecessors, err := admitSendPredecessors(ctx, query, row, scope, profile, now)
	if err != nil {
		return err
	}
	// Family history and predecessor transitions remain provisional until the
	// caller commits challenge, encrypted delivery, audit and journal together.
	if err := persistSendWindow(ctx, exec, row, mustIssueProfile(profile), now); err != nil {
		return err
	}
	if profile.Replacement == otp.ReplacePrevious {
		for _, old := range predecessors {
			n, err := exec(ctx, `UPDATE `+row.schema+`.challenges SET state='revoked',version=$4::numeric,terminal_at=$5
 WHERE tenant_id=$1 AND challenge_id=$2 AND version=$3::numeric AND state='issued' AND send_family_digest=$6
 AND issued_at<=$5::timestamptz AND $5::timestamptz<=clock_timestamp()`, row.tenant, old.id, strconv.FormatUint(old.version, 10), strconv.FormatUint(old.version+1, 10), now, row.digest[:])
			if err != nil {
				return challengeFailure(ctx)
			}
			if n != 1 {
				return ErrInvalidCommand
			}
		}
	}
	replacement := "retain"
	if profile.Replacement == otp.ReplacePrevious {
		replacement = "replace"
	}
	// Take the original canonical fingerprint from its owning kernel claim,
	// not a caller-selected value or another journal. Pending state is required:
	// exact terminal replay must be resolved before entering this new-use path.
	n, err := exec(ctx, `INSERT INTO `+row.schema+`.challenges(
 tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,
 digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,
 maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version,send_family_digest)
 SELECT $1::text,$2::text,$3::text,$4::text,$5::bytea,'identity.otp.send',j.fingerprint,$6,$7,$8,$9::numeric,$10::numeric,$11,$12,$13,$14,
 $15,$16,$17,$18,$19,$20,$21,$22,'issued',1,$23
 FROM identity.identity_command_id_claims j JOIN identity.commands k USING(command_id,tenant_id,purpose)
 WHERE j.command_id=$5 AND j.tenant_id=$1 AND j.purpose='identity.otp.send' AND k.state='pending'
 AND $21::timestamptz<=clock_timestamp() AND $22::timestamptz>clock_timestamp()
 AND EXISTS(SELECT 1 FROM `+row.schema+`.send_families f WHERE f.tenant_id=$1 AND f.scope_digest=$23
 AND f.version=$24::numeric AND f.sent_at[cardinality(f.sent_at)]=$25::timestamptz)`, row.tenant, scope.ChallengeID, scope.SubjectID, string(scope.Purpose), command,
		int64(s.Digest.KeyVersion), s.Digest.Value[:], scopeDigest.Value[:], strconv.FormatUint(scope.PolicyVersion, 10), strconv.FormatUint(scope.Generation, 10), profile.Alphabet, int64(profile.Length), profile.TTL.Microseconds(), profile.ResendInterval.Microseconds(), int64(profile.MaximumSends), int64(profile.Attempts), replacement, checks.Enabled, int64(checks.MaximumChecks), checks.LockoutAfter.Microseconds(), s.IssuedAt, s.ExpiresAt, row.digest[:], strconv.FormatUint(row.version+1, 10), now)
	if err != nil {
		return challengeFailure(ctx)
	}
	if n != 1 {
		return ErrInvalidCommand
	}
	return ctx.Err()
}

// The checked profile has already passed the immutable Challenge constructor;
// no policy changes or defaults can enter this private reconstruction.
func mustIssueProfile(s otp.CodeProfileSpec) otp.CodeProfile {
	p, _ := otp.NewCodeProfile(s)
	return p
}

type issuancePredecessor struct {
	id, state string
	version   uint64
	issuedAt  time.Time
}

// Both issued and suppressed requests share denial admission for unresolved
// legacy or reserved predecessors. Only issuance may mutate these challenges;
// suppression cannot disclose their presence by skipping this check.
func admitSendPredecessors(ctx context.Context, query challengeQuery, row lockedSendFamily, scope otp.DigestScopeSpec, profile otp.CodeProfileSpec, now time.Time) ([]issuancePredecessor, error) {
	predecessors, err := lockIssuancePredecessors(ctx, query, row, scope, now)
	if err != nil {
		return nil, err
	}
	if profile.Replacement == otp.ReplacePrevious {
		for _, old := range predecessors {
			if old.state != "issued" || old.version == ^uint64(0) || now.Before(old.issuedAt) {
				return nil, ErrInvalidCommand
			}
		}
	}
	return predecessors, nil
}

func lockIssuancePredecessors(ctx context.Context, query challengeQuery, row lockedSendFamily, scope otp.DigestScopeSpec, now time.Time) ([]issuancePredecessor, error) {
	// Existing populated state has no reversible destination. Do not attach it
	// to a guessed family or let a reissue bypass its unresolved authority.
	legacy, err := query(ctx, `SELECT 1 FROM (
 (SELECT 1 FROM `+row.schema+`.challenges WHERE tenant_id=$1 AND purpose=$2 AND subject_id=$3
 AND send_family_digest IS NULL AND state='issued' AND expires_at>$4::timestamptz ORDER BY expires_at LIMIT 1)
 UNION ALL
 (SELECT 1 FROM `+row.schema+`.challenges WHERE tenant_id=$1 AND purpose=$2 AND subject_id=$3
 AND send_family_digest IS NULL AND state='reserved' LIMIT 1)
 ) live LIMIT 1`, row.tenant, string(scope.Purpose), scope.SubjectID, now)
	if err != nil {
		return nil, challengeFailure(ctx)
	}
	if legacy == nil {
		return nil, ErrUnavailable
	}
	active := legacy.Next()
	legacyErr := legacy.Err()
	legacy.Close()
	if legacyErr != nil {
		return nil, challengeFailure(ctx)
	}
	if active {
		return nil, ErrInvalidCommand
	}
	// Locked original-flow/shared-abuse owners fence concurrent reservation
	// before this private helper. Expired issued tombstones grant no new code
	// authority, but reserved custody remains unresolved regardless of expiry.
	// Each indexed candidate lane is bounded before union/sort/row locking.
	rows, err := query(ctx, `WITH candidates AS MATERIALIZED(
 (SELECT challenge_id FROM `+row.schema+`.challenges WHERE tenant_id=$1 AND send_family_digest=$2
 AND state='issued' AND expires_at>$3::timestamptz ORDER BY expires_at,challenge_id LIMIT 11)
 UNION ALL
 (SELECT challenge_id FROM `+row.schema+`.challenges WHERE tenant_id=$1 AND send_family_digest=$2
 AND state='reserved' ORDER BY challenge_id LIMIT 11)
 ) SELECT e.challenge_id,e.state,e.version::text,e.issued_at,e.subject_id,e.purpose FROM `+row.schema+`.challenges e
 JOIN candidates c ON c.challenge_id=e.challenge_id WHERE e.tenant_id=$1 AND e.send_family_digest=$2
 AND (e.state='reserved' OR (e.state='issued' AND e.expires_at>$3::timestamptz))
 ORDER BY e.challenge_id LIMIT 11 FOR UPDATE OF e`, row.tenant, row.digest[:], now)
	if err != nil {
		return nil, challengeFailure(ctx)
	}
	if rows == nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []issuancePredecessor
	for rows.Next() {
		var v, subject, purpose string
		var old issuancePredecessor
		if len(out) == 10 || rows.Scan(&old.id, &old.state, &v, &old.issuedAt, &subject, &purpose) != nil {
			return nil, ErrUnavailable
		}
		old.version, err = strconv.ParseUint(v, 10, 64)
		if err != nil || old.version == 0 || strconv.FormatUint(old.version, 10) != v || !nativeTime(old.issuedAt) || subject != scope.SubjectID || purpose != string(scope.Purpose) {
			return nil, ErrUnavailable
		}
		out = append(out, old)
	}
	if rows.Err() != nil {
		return nil, challengeFailure(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
