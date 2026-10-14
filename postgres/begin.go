package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// journalWorkFence is a coordinator-private Begin observation. It is not a
// public Work and cannot enlist contributors or execute/close a transaction.
// The coordinator must bound its domain context by the remaining lease and
// recheck ownership at terminalization; this snapshot cannot renew authority.
type journalWorkFence struct {
	generation  uint64
	now, until  time.Time
	readStarted time.Time
}

// beginJournal revalidates the admitted command and locks its pending journal
// before the sole coordinator can construct domain Work. The caller owns the
// transaction, all participant checks and rollback on every failure. In
// particular a missing claim may be provisionally inserted by claim admission,
// but it is an integrity failure here and must never be committed or repaired.
// Global claim and command locks are retained until caller closure, preventing
// concurrent takeover while this transaction applies domain effects.
func beginJournal(ctx context.Context, tx pgx.Tx, q claimRequest, keys claimKeys, r journalReservation, owner [16]byte) (journalWorkFence, error) {
	if ctx == nil || tx == nil || r.disposition != journalOwned || r.generation == 0 || owner == ([16]byte{}) {
		return journalWorkFence{}, identity.InvalidInputError{Field: "command_begin"}
	}
	d, err := lockCommandClaim(ctx, tx, q, keys)
	if err != nil {
		return journalWorkFence{}, err
	}
	if d == claimConflict {
		return journalWorkFence{}, identity.ConflictError{}
	}
	if d != claimReplay {
		return journalWorkFence{}, identity.UnavailableError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var state, generation *string
	var actualOwner []byte
	var until *time.Time
	err = tx.QueryRow(ctx, `SELECT state,generation::text,lease_owner,lease_until FROM identity.commands
WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose).Scan(&state, &generation, &actualOwner, &until)
	if err != nil {
		return journalWorkFence{}, readFailure(ctx, err)
	}
	if state == nil || generation == nil || until == nil || len(actualOwner) != len(owner) || !postgresExactTime(*until) {
		return journalWorkFence{}, identity.UnavailableError{}
	}
	gen, err := strconv.ParseUint(*generation, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != *generation {
		return journalWorkFence{}, identity.UnavailableError{}
	}
	if *state != "pending" || gen != r.generation || [16]byte(actualOwner) != owner {
		return journalWorkFence{}, identity.ConflictError{}
	}
	// Time read before either lock wait could extend expired ownership. Read
	// only after both locks; a live reservation is not itself fresh authority.
	var now time.Time
	readStarted := time.Now()
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return journalWorkFence{}, readFailure(ctx, err)
	}
	if ctx.Err() != nil {
		return journalWorkFence{}, readFailure(ctx, ctx.Err())
	}
	if !postgresExactTime(now) {
		return journalWorkFence{}, identity.UnavailableError{}
	}
	if !until.After(now) {
		return journalWorkFence{}, identity.ConflictError{}
	}
	return journalWorkFence{generation: gen, now: now.UTC(), until: until.UTC(), readStarted: readStarted}, nil
}
