package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Preparation is a phase of the existing command journal, not independent
// execution authority. generate is eligibility to commit the start marker;
// it is never permission to run entropy before that commit is acknowledged.
// The feature owns authenticated encryption/opening of output. This layer
// retains only its bounded ciphertext and original generation provenance.
type preparationReservation struct {
	journal          journalReservation
	generate         bool
	output           []byte
	outputGeneration uint64
}

// Call only after lockCommandClaim has matched the immutable original intent.
// All closure remains with the coordinator. No callbacks or network work run
// while the journal lock is held. An expired lease can transfer ownership,
// but can never infer that randomness was not used from absent ciphertext.
func reservePreparationJournal(ctx context.Context, tx pgx.Tx, q claimRequest, d claimDisposition, owner [16]byte, lease time.Duration) (preparationReservation, error) {
	if !validJournalInput(ctx, tx, q, owner, lease) || (d != claimNew && d != claimReplay) {
		return preparationReservation{}, invalidPreparation()
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	if d == claimNew {
		journal, err := reserveJournal(ctx, tx, q, d, owner, lease)
		if err != nil {
			return preparationReservation{}, err
		}
		tag, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_profile=1 WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND preparation_profile IS NULL AND command_plan IS NULL`, id, string(q.tenant), q.purpose)
		if err != nil {
			return preparationReservation{}, readFailure(ctx, err)
		}
		if tag.RowsAffected() != 1 {
			return preparationReservation{}, identity.ConflictError{}
		}
		return preparationReservation{journal: journal, generate: true}, nil
	}
	var profile *int16
	var started, provenance *string
	var output, plan []byte
	var state, generation, attempt string
	var until time.Time
	err := tx.QueryRow(ctx, `SELECT preparation_profile,preparation_started_generation::text,preparation_ciphertext_generation::text,preparation_ciphertext,command_plan,state,generation::text,attempt::text,lease_until
FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose).Scan(&profile, &started, &provenance, &output, &plan, &state, &generation, &attempt, &until)
	if err != nil {
		return preparationReservation{}, readFailure(ctx, err)
	}
	if profile == nil || *profile != 1 || plan != nil || !postgresExactTime(until) {
		return preparationReservation{}, identity.ConflictError{}
	}
	gen, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || gen == 0 {
		return preparationReservation{}, identity.UnavailableError{}
	}
	tries, err := strconv.ParseUint(attempt, 10, 64)
	if err != nil || tries < gen {
		return preparationReservation{}, identity.UnavailableError{}
	}
	var original uint64
	if started != nil {
		original, err = strconv.ParseUint(*started, 10, 64)
		if err != nil || original == 0 || original > gen {
			return preparationReservation{}, identity.UnavailableError{}
		}
	}
	if output != nil {
		if original == 0 || provenance == nil || len(output) < 1 || len(output) > maximumPreparationCiphertext {
			return preparationReservation{}, identity.UnavailableError{}
		}
		v, err := strconv.ParseUint(*provenance, 10, 64)
		if err != nil || v != original {
			return preparationReservation{}, identity.UnavailableError{}
		}
	} else if provenance != nil {
		return preparationReservation{}, identity.UnavailableError{}
	}
	if state == "pending" && original != 0 && output == nil {
		// Once marked, even an expired abandoned owner may have generated output.
		// Do not advance the generation, disclose partial custody or renew it.
		return preparationReservation{journal: journalReservation{disposition: journalBusy, generation: gen, attempt: tries, retryAfter: time.Minute}}, nil
	}
	journal, err := reserveJournal(ctx, tx, q, d, owner, lease)
	if err != nil {
		return preparationReservation{}, err
	}
	r := preparationReservation{journal: journal}
	if journal.disposition == journalOwned {
		r.generate = original == 0
		if !r.generate {
			r.output, r.outputGeneration = bytes.Clone(output), original
		}
	}
	return r, nil
}

const maximumPreparationCiphertext = 1 << 20

// startJournalPreparation durably fences entropy before it is invoked outside
// the transaction. Even the same live owner cannot start twice. A lost commit
// acknowledgement never authorizes generation; retry must observe the journal.
func startJournalPreparation(ctx context.Context, tx pgx.Tx, q claimRequest, r journalReservation, owner [16]byte) error {
	if err := lockPreparationOwner(ctx, tx, q, r, owner); err != nil {
		return err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	tag, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_started_generation=generation WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND preparation_started_generation IS NULL AND preparation_ciphertext IS NULL`, id, string(q.tenant), q.purpose)
	if err != nil {
		return readFailure(ctx, err)
	}
	if tag.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// retainJournalPreparation accepts only the original marked live generation.
// An exact retry can acknowledge the same bytes; it cannot replace them.
// Takeover owns resumption of retained output, not creation of a new output.
func retainJournalPreparation(ctx context.Context, tx pgx.Tx, q claimRequest, r journalReservation, owner [16]byte, ciphertext []byte) error {
	if len(ciphertext) < 1 || len(ciphertext) > maximumPreparationCiphertext {
		return invalidPreparation()
	}
	if err := lockPreparationOwner(ctx, tx, q, r, owner); err != nil {
		return err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var started *string
	var stored []byte
	if err := tx.QueryRow(ctx, `SELECT preparation_started_generation::text,preparation_ciphertext FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, id, string(q.tenant), q.purpose).Scan(&started, &stored); err != nil {
		return readFailure(ctx, err)
	}
	if started == nil || *started != strconv.FormatUint(r.generation, 10) {
		return identity.ConflictError{}
	}
	if stored != nil {
		if !bytes.Equal(stored, ciphertext) {
			return identity.ConflictError{}
		}
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$4,preparation_ciphertext_generation=generation WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND preparation_ciphertext IS NULL`, id, string(q.tenant), q.purpose, ciphertext)
	if err != nil {
		return readFailure(ctx, err)
	}
	if tag.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func lockPreparationOwner(ctx context.Context, tx pgx.Tx, q claimRequest, r journalReservation, owner [16]byte) error {
	if !validJournalInput(ctx, tx, q, owner, time.Microsecond) || r.disposition != journalOwned || r.generation == 0 {
		return invalidPreparation()
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var matched bool
	var until time.Time
	// Read time after the row lock, never before a competing transaction wait.
	err := tx.QueryRow(ctx, `SELECT state='pending' AND generation=$4::numeric AND lease_owner=$5 AND preparation_profile=1 AND command_plan IS NULL,lease_until FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose, strconv.FormatUint(r.generation, 10), owner[:]).Scan(&matched, &until)
	if err != nil {
		return readFailure(ctx, err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return readFailure(ctx, err)
	}
	if !matched || !until.After(now) {
		return identity.ConflictError{}
	}
	return nil
}

func invalidPreparation() error { return identity.InvalidInputError{Field: "command_preparation"} }
