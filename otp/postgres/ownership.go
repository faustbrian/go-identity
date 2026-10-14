package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// Native persistence only. A binding is data, not admission or noncommit proof.
// Future native participant callbacks must obtain it from the exact sealed
// coordinator phase handle, and check current primary flow/lockout before use.
// These helpers have no public dispatch, transaction owner, replay journal,
// callback provider, code oracle or way to infer rollback from expiry.
type lockedReservation struct {
	schema                          string
	subject                         string
	binding                         identitypostgres.OTPReservationBinding
	version, generation             uint64
	issuedAt, expiresAt, reservedAt time.Time
}
type reservationTerminal uint8

const (
	reservationFinalized reservationTerminal = iota + 1
	reservationReleased
)

func nativeTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func ownershipID(s string) ([]byte, bool) {
	if len(s) != 22 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) == 16 && [16]byte(b) != ([16]byte{})
}

func validOwnership(b identitypostgres.OTPReservationBinding) bool {
	_, command := ownershipID(string(b.Command.CommandID))
	_, attempt := ownershipID(b.Plan.AttemptID)
	return command && attempt && len(b.Command.TenantID) > 0 && len(b.Command.TenantID) <= 256 && len(b.Command.UserID) <= 256 && len(b.Command.OperationID) > 0 && len(b.Command.OperationID) <= 256 && len(b.Plan.ChallengeID) > 0 && len(b.Plan.ChallengeID) <= 256 && b.Plan.Mode == identitypostgres.OTPConsume && b.Plan.ExpectedVersion > 0 && b.Plan.ExpectedVersion < ^uint64(0) && b.Plan.FingerprintKeyVersion > 0 && b.Plan.DigestKeyVersion > 0 && b.Plan.AttemptFingerprint != ([32]byte{}) && b.Plan.ScopeDigest != ([32]byte{}) && b.Fingerprint != ([32]byte{}) && b.Generation > 0
}

// persistReservation consumes exactly one comparison allowance and stores the
// original complete command/attempt/generation linkage. The core decision is
// provisional until this sole reservation transaction commits. Same-command
// replay must be resolved by the coordinator before reaching this new-use path.
func persistReservation(ctx context.Context, exec challengeExec, row lockedChallenge, d otp.AttemptDecision, b identitypostgres.OTPReservationBinding, now time.Time) error {
	return persistOriginalReservation(ctx, exec, row, d, b, now, nil)
}

// Legacy private callers retain their historical storage profile. Native
// consuming dispatch always supplies authenticated original custody and attaches
// it in this same counted state transition, never a second state update.
func persistOriginalReservation(ctx context.Context, exec challengeExec, row lockedChallenge, d otp.AttemptDecision, b identitypostgres.OTPReservationBinding, now time.Time, original *identity.FeatureCommandSpec) error {
	if ctx == nil || exec == nil || !nativeTime(now) || !validOwnership(b) || b.PreviousGeneration != 0 || row.schema == "" || row.command != b.Command || row.plan != b.Plan {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := row.challenge.Bindings()
	// Admission must leave one version increment for terminalization; otherwise
	// even a proven rollback could not release the reserved challenge.
	if err != nil || s.State != otp.ChallengeIssued || s.Version >= ^uint64(0)-1 || s.Version != b.Plan.ExpectedVersion || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || d.Outcome != otp.AttemptReserved || d.State != otp.ChallengeReserved || d.Version != s.Version+1 || d.UsedAttempts != s.UsedAttempts+1 || d.FailedAttempts != s.FailedAttempts || d.Checks != s.Checks || d.LockoutAfter != 0 {
		return ErrInvalidCommand
	}
	id, _ := ownershipID(string(b.Command.CommandID))
	extra := ""
	args := []any{row.tenant, row.id, int64(row.keyVersion), row.scopeDigest[:], strconv.FormatUint(s.Version, 10), strconv.FormatUint(d.Version, 10), int64(d.UsedAttempts), id, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.AttemptID, b.Plan.AttemptFingerprint[:], int64(b.Plan.FingerprintKeyVersion), now}
	if original != nil {
		wire, err := originalEnvelope(*original, b)
		if err != nil {
			return err
		}
		extra = ",consumer_envelope=$16,consumer_owner=$17,consumer_record_requirement=$18,consumer_subject_requirement=$19"
		args = append(args, wire, original.Operation.Owner, int16(original.Operation.RecordRequirement), int16(original.Operation.SubjectRequirement))
	}
	count, err := exec(ctx, `UPDATE `+row.schema+`.challenges SET state='reserved',version=$6::numeric,used_attempts=$7,
 consumer_command_id=$8,consumer_purpose=$9,consumer_fingerprint=$10,consumer_generation=$11::numeric,
 consumer_attempt_id=$12,consumer_attempt_fingerprint=$13,consumer_issuer_version=$14,reserved_at=$15`+extra+`
 WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4 AND version=$5::numeric
 AND state='issued' AND issued_at<=clock_timestamp() AND expires_at>clock_timestamp()`, args...)
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

// loadReservation locks exact original ownership without code/ciphertext or
// decryption. Thus authoritative noncommit can release an expired reservation
// without reviving a challenge or depending on submitted-code retention. It
// grants no live expiry, flow authority or noncommit proof; phase checks follow.
// Subject comes from authenticated native attempt scope, not the anonymous
// command's UserID. Retain it for every terminal/rebind CAS on this locked row.
func loadReservation(ctx context.Context, query challengeQuery, schema string, b identitypostgres.OTPReservationBinding, expected uint64, subject string) (lockedReservation, error) {
	bad := func(err error) (lockedReservation, error) { return lockedReservation{}, err }
	if ctx == nil || query == nil || !validSchema(schema) || !validOwnership(b) || expected == 0 || len(subject) > 256 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	id, _ := ownershipID(string(b.Command.CommandID))
	quoted := pgx.Identifier{schema}.Sanitize()
	rows, err := query(ctx, `SELECT version::text,consumer_generation::text,issued_at,expires_at,reserved_at
 FROM `+quoted+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4
 AND subject_id=$5 AND state='reserved' AND consumer_command_id=$6 AND consumer_purpose=$7 AND consumer_fingerprint=$8
 AND consumer_generation=$9::numeric AND consumer_attempt_id=$10 AND consumer_attempt_fingerprint=$11 AND consumer_issuer_version=$12 FOR UPDATE`, string(b.Command.TenantID), b.Plan.ChallengeID, int64(b.Plan.DigestKeyVersion), b.Plan.ScopeDigest[:], subject, id, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(expected, 10), b.Plan.AttemptID, b.Plan.AttemptFingerprint[:], int64(b.Plan.FingerprintKeyVersion))
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
	var version, generation string
	var issued, expires, reserved time.Time
	if rows.Scan(&version, &generation, &issued, &expires, &reserved) != nil || rows.Next() || rows.Err() != nil {
		return bad(challengeFailure(ctx))
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != version || v <= b.Plan.ExpectedVersion || generation != strconv.FormatUint(expected, 10) || !nativeTime(issued) || !nativeTime(expires) || !nativeTime(reserved) || !expires.After(issued) || reserved.Before(issued) || !reserved.Before(expires) {
		return bad(ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return lockedReservation{schema: quoted, subject: subject, binding: b, version: v, generation: expected, issuedAt: issued, expiresAt: expires, reservedAt: reserved}, nil
}

// rebindReservation requires the exact successor and never compares, charges,
// changes original times or transfers any sibling participant separately.
// Only the sole coordinator's all-participant takeover may commit this CAS.
func rebindReservation(ctx context.Context, exec challengeExec, row lockedReservation, b identitypostgres.OTPReservationBinding, now time.Time) error {
	// A takeover must preserve the same terminal version capacity as admission.
	if ctx == nil || exec == nil || !nativeTime(now) || row.schema == "" || row.binding != b || !validOwnership(b) || row.version >= ^uint64(0)-1 || row.generation == 0 || row.generation != b.PreviousGeneration || b.PreviousGeneration == ^uint64(0) || b.Generation != b.PreviousGeneration+1 || now.Before(row.reservedAt) || !now.Before(row.expiresAt) {
		return ErrInvalidCommand
	}
	return updateReservation(ctx, exec, row, b, "reserved", now, true)
}

// terminalReservation only projects an already authorized native phase.
// Finalize must share the protected domain mutation's commit and recheck all
// current owners. Release MUST originate from sealed OTPReleaseWork after the
// coordinator proves rollback/unanimous noncommit; this helper is not that proof.
// Neither expiry, a matching binding nor an error permits calling release.
func terminalReservation(ctx context.Context, exec challengeExec, row lockedReservation, b identitypostgres.OTPReservationBinding, target reservationTerminal, now time.Time) error {
	if ctx == nil || exec == nil || !nativeTime(now) || row.schema == "" || row.binding != b || !validOwnership(b) || row.version == ^uint64(0) || row.generation == 0 || now.Before(row.reservedAt) {
		return ErrInvalidCommand
	}
	switch target {
	case reservationFinalized:
		if b.PreviousGeneration != 0 || row.generation != b.Generation || !now.Before(row.expiresAt) {
			return ErrInvalidCommand
		}
		return updateReservation(ctx, exec, row, b, "finalized", now, true)
	case reservationReleased:
		if b.PreviousGeneration != row.generation || b.Generation != row.generation && (row.generation == ^uint64(0) || b.Generation != row.generation+1) {
			return ErrInvalidCommand
		}
		return updateReservation(ctx, exec, row, b, "released", now, false)
	default:
		return ErrInvalidCommand
	}
}

func updateReservation(ctx context.Context, exec challengeExec, row lockedReservation, b identitypostgres.OTPReservationBinding, state string, now time.Time, live bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id, _ := ownershipID(string(b.Command.CommandID))
	count, err := exec(ctx, `UPDATE `+row.schema+`.challenges SET state=$13,version=$14::numeric,consumer_generation=$15::numeric,
 terminal_at=CASE WHEN $13='reserved' THEN NULL ELSE $16::timestamptz END
 WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4 AND subject_id=$5
 AND state='reserved' AND consumer_command_id=$6 AND consumer_purpose=$7 AND consumer_fingerprint=$8
 AND consumer_generation=$9::numeric AND consumer_attempt_id=$10 AND consumer_attempt_fingerprint=$11 AND consumer_issuer_version=$12
 AND version=$17::numeric AND (NOT $18 OR (issued_at<=clock_timestamp() AND expires_at>clock_timestamp()))`, string(b.Command.TenantID), b.Plan.ChallengeID, int64(b.Plan.DigestKeyVersion), b.Plan.ScopeDigest[:], row.subject, id, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(row.generation, 10), b.Plan.AttemptID, b.Plan.AttemptFingerprint[:], int64(b.Plan.FingerprintKeyVersion), state, strconv.FormatUint(row.version+1, 10), strconv.FormatUint(b.Generation, 10), now, strconv.FormatUint(row.version, 10), live)
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
