package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This is only the coordinator's final journal write, never commit/rollback or
// independently minted mutation authority. Required contributor finalization
// and staged audit must be proven before its future public caller invokes it.
func terminalizeJournal(ctx context.Context, tx pgx.Tx, q claimRequest, r journalReservation, owner [16]byte, result identity.CommandResult, class string) error {
	if !validJournalInput(ctx, tx, q, owner, time.Minute) || r.disposition != journalOwned || r.generation == 0 {
		return identity.InvalidInputError{Field: "command_terminal"}
	}
	state := "aborted"
	if result.Outcome == identity.CommitOutcomeCommitted {
		if class != "committed" {
			return identity.InvalidInputError{Field: "command_terminal"}
		}
		state = "committed"
	} else {
		if class == "reauthentication-required" && (q.feature == nil || !oauthReauthenticationOperation(*q.feature)) {
			return identity.InvalidInputError{Field: "command_terminal"}
		}
		switch class {
		case "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure", "reauthentication-required":
		default:
			return identity.InvalidInputError{Field: "command_terminal"}
		}
	}
	body, e := encodeJournalResult(q, result)
	if e != nil {
		return e
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var matched, preparedAccountLink bool
	e = tx.QueryRow(ctx, `SELECT state='pending' AND generation=$4::numeric AND lease_owner=$5,
CASE WHEN $6 THEN coalesce(to_jsonb(j)->>'preparation_profile','')='5' ELSE false END
FROM identity.commands j WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.tenant), q.purpose, strconv.FormatUint(r.generation, 10), owner[:], q.purpose == "identity.account.link-token" && q.feature == nil).Scan(&matched, &preparedAccountLink)
	if e != nil {
		return readFailure(ctx, e)
	}
	if !matched {
		return identity.ConflictError{}
	}
	// RP-start preparation temporarily carries encrypted PKCE/state custody.
	// Once terminal, its native transaction row is the sole secret owner so the
	// RP profile's later erasure cannot leave a recoverable journal duplicate
	// (REFERENCE_CONFIGURATION.md, struct:ref.oauth.rp_transaction). Pending and
	// uncertain starts retain original recovery output. Prepared root links also
	// erase their temporary provider-response/issuance checkpoint only alongside
	// the definitive receipt (TRANSACTION_CONTRACT.md, provider effects). Profile
	// detection uses row metadata so ordinary schemas need no optional columns;
	// scope-only recovery does not require the original request's secret input.
	preparationErasure := ""
	if oauthRPInitiationClaim(q) || preparedAccountLink {
		preparationErasure = ",preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL"
	}
	// Ordinary installations need not select the optional preparation schema.
	// Their unchanged SQL must not even reference its absent columns.
	tag, e := tx.Exec(ctx, `WITH instant AS (SELECT clock_timestamp() AS now)
UPDATE identity.commands SET state=$4,result_version=1,terminal_class=$5,result=$6,terminal_at=instant.now,updated_at=instant.now`+preparationErasure+`
FROM instant WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND lease_until>instant.now`, id, string(q.tenant), q.purpose, state, class, body)
	if e != nil {
		return readFailure(ctx, e)
	}
	if tag.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	return nil
}
