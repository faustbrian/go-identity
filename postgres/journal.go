package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type journalDisposition uint8

const (
	journalInvalid journalDisposition = iota
	journalOwned
	journalBusy
)

// This private snapshot is not public apply authority. A takeover must rebind
// every participant in the same transaction before the coordinator commits it.
type journalReservation struct {
	disposition                             journalDisposition
	generation, previousGeneration, attempt uint64
	retryAfter                              time.Duration
}

// reserveJournal runs only after the global claim has been locked and matched.
// It owns neither transaction closure nor participant reservations. The sole
// coordinator must roll back the whole transaction on any subsequent failure.
func reserveJournal(ctx context.Context, tx pgx.Tx, q claimRequest, d claimDisposition, owner [16]byte, lease time.Duration) (journalReservation, error) {
	if !validJournalInput(ctx, tx, q, owner, lease) || (d != claimNew && d != claimReplay) {
		return journalReservation{}, identity.InvalidInputError{Field: "command_journal"}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	if d == claimNew {
		_, e := tx.Exec(ctx, `WITH instant AS (SELECT clock_timestamp() AS now)
INSERT INTO identity.commands(command_id,tenant_id,purpose,state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)
SELECT $1,$2,$3,'pending',1,1,$4,now+($5::bigint*interval '1 microsecond'),now,now,now FROM instant`, id, string(q.tenant), q.purpose, owner[:], lease.Microseconds())
		if e != nil {
			return journalReservation{}, readFailure(ctx, e)
		}
		return journalReservation{disposition: journalOwned, generation: 1, attempt: 1}, nil
	}
	var state, generation, attempt *string
	var until *time.Time
	e := tx.QueryRow(ctx, `SELECT state,generation::text,attempt::text,lease_until FROM identity.commands
WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose).Scan(&state, &generation, &attempt, &until)
	if e != nil {
		return journalReservation{}, readFailure(ctx, e)
	}
	if state == nil || *state != "pending" || generation == nil || attempt == nil || until == nil || !postgresExactTime(*until) {
		return journalReservation{}, identity.UnavailableError{}
	}
	gen, e := strconv.ParseUint(*generation, 10, 64)
	if e != nil || gen == 0 {
		return journalReservation{}, identity.UnavailableError{}
	}
	tries, e := strconv.ParseUint(*attempt, 10, 64)
	if e != nil || tries < gen {
		return journalReservation{}, identity.UnavailableError{}
	}
	// Read after acquiring the row lock: lock wait must not extend old authority.
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return journalReservation{}, readFailure(ctx, e)
	}
	if until.After(now) {
		retry := until.Sub(now)
		if retry > time.Minute {
			retry = time.Minute
		}
		return journalReservation{disposition: journalBusy, generation: gen, attempt: tries, retryAfter: retry}, nil
	}
	if gen == ^uint64(0) || tries == ^uint64(0) {
		return journalReservation{}, identity.UnavailableError{}
	}
	tag, e := tx.Exec(ctx, `UPDATE identity.commands SET generation=generation+1,attempt=attempt+1,
lease_owner=$4,lease_until=$5::timestamptz+($6::bigint*interval '1 microsecond'),heartbeat_at=$5,updated_at=$5
WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND state='pending' AND generation=$7::numeric`, id, string(q.tenant), q.purpose, owner[:], now, lease.Microseconds(), strconv.FormatUint(gen, 10))
	if e != nil {
		return journalReservation{}, readFailure(ctx, e)
	}
	if tag.RowsAffected() != 1 {
		return journalReservation{}, identity.UnavailableError{}
	}
	return journalReservation{disposition: journalOwned, generation: gen + 1, previousGeneration: gen, attempt: tries + 1}, nil
}

// heartbeatJournal renews only live current ownership. It does not reacquire an
// expired lease, begin domain work, commit, or prove an execution outcome.
func heartbeatJournal(ctx context.Context, tx pgx.Tx, q claimRequest, r journalReservation, owner [16]byte, lease time.Duration) error {
	if !validJournalInput(ctx, tx, q, owner, lease) || r.disposition != journalOwned || r.generation == 0 {
		return identity.InvalidInputError{Field: "command_heartbeat"}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	// Lock first; a database timestamp evaluated before a wait is stale evidence.
	var matched bool
	e := tx.QueryRow(ctx, `SELECT state='pending' AND generation=$4::numeric AND lease_owner=$5
FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose, strconv.FormatUint(r.generation, 10), owner[:]).Scan(&matched)
	if e != nil {
		return readFailure(ctx, e)
	}
	if !matched {
		return identity.ConflictError{}
	}
	tag, e := tx.Exec(ctx, `WITH instant AS (SELECT clock_timestamp() AS now)
UPDATE identity.commands SET lease_until=instant.now+($4::bigint*interval '1 microsecond'),heartbeat_at=instant.now,updated_at=instant.now
FROM instant WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND lease_until>instant.now`, id, string(q.tenant), q.purpose, lease.Microseconds())
	if e != nil {
		return readFailure(ctx, e)
	}
	if tag.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func validJournalInput(ctx context.Context, tx pgx.Tx, q claimRequest, owner [16]byte, lease time.Duration) bool {
	if ctx == nil || tx == nil || owner == ([16]byte{}) || lease < time.Microsecond || lease > time.Minute || lease%time.Microsecond != 0 {
		return false
	}
	if _, ok := ctx.Deadline(); !ok {
		return false
	}
	_, e := identity.ParseCommandID(string(q.commandID))
	return e == nil && len(q.tenant) > 0 && len(q.purpose) > 0
}
