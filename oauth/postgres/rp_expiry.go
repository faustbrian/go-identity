package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type rpExpiryPosition struct {
	expires time.Time
	tenant  string
	id      string
}

type rpExpiredTransaction struct {
	position rpExpiryPosition
	provider string
	origin   []byte
	digest   []byte
	binding  []byte
	issued   time.Time
}

// EraseExpiredUnused removes PKCE and state-proof ciphertext for expired,
// abandoned explicit-link transactions. It is a trusted backend maintenance
// operation, not an HTTP endpoint or authorization/reconciliation mechanism.
// It never decrypts PKCE, changes capability state, exchanges a code or erases a
// transaction with any callback command claim, including unresolved exchanges.
//
// maximum bounds examined rows to 1..100. Pass an empty cursor initially, then
// the returned cursor until it is empty. Cursors contain only expiry and row
// identifiers; they grant no authority. Claimed rows advance pagination without
// erasure, so uncertain exchanges cannot starve later abandoned transactions.
// Run another sweep from the beginning to revisit skipped locked rows. The caller
// owns scheduling; the service creates no goroutines or background timer.
//
// A batch commits atomically. On error, counts/cursors are withheld; a failed
// commit acknowledgement has an unknown outcome and may be retried safely.
// Retain the configured provider/key snapshot until its RP custody is drained.
// Concurrent maintenance calls use independent bounded transactions and skip
// locked rows. Earlier caller deadlines win; the caller-owned pool stays open.
func (s *LinkService) EraseExpiredUnused(ctx context.Context, maximum int, cursor string) (erased int, next string, err error) {
	if s == nil || s.pool == nil || s.pool.Raw() == nil || s.config == nil || ctx == nil || maximum < 1 || maximum > 100 {
		return 0, "", identity.InvalidInputError{Field: "oauth_expiry"}
	}
	after, err := parseRPExpiryCursor(cursor)
	if err != nil {
		return 0, "", err
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	failure := func() (int, string, error) {
		if ctx.Err() != nil {
			return 0, "", ctx.Err()
		}
		return 0, "", identity.UnavailableError{}
	}
	tx, err := s.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure()
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), s.config().MaximumDuration)
		defer cancel()
		_ = tx.Rollback(cleanup)
		if recover() != nil {
			erased, next, err = 0, "", identity.UnavailableError{}
		}
	}()
	rows, err := tx.Query(ctx, `SELECT expires_at,tenant_id,transaction_id,provider_id,origin_command_id,state_digest,binding_ciphertext,issued_at
 FROM `+rpQuotedSchema(s.config().Schema)+`.transactions
 WHERE operation='identity.account.link-start' AND version=1 AND secrets_erased_at IS NULL
 AND expires_at<=clock_timestamp() AND (expires_at,tenant_id,transaction_id)>($1,$2,$3)
 ORDER BY expires_at,tenant_id,transaction_id LIMIT $4 FOR UPDATE SKIP LOCKED`, after.expires, after.tenant, after.id, maximum)
	if err != nil {
		return failure()
	}
	defer rows.Close()
	candidates := make([]rpExpiredTransaction, 0, maximum)
	for rows.Next() {
		var candidate rpExpiredTransaction
		if rows.Scan(&candidate.position.expires, &candidate.position.tenant, &candidate.position.id, &candidate.provider, &candidate.origin, &candidate.digest, &candidate.binding, &candidate.issued) != nil || len(candidates) >= maximum {
			return failure()
		}
		candidates = append(candidates, candidate)
	}
	if rows.Err() != nil {
		return failure()
	}
	rows.Close()
	for _, candidate := range candidates {
		profile, ok := s.profiles[candidate.provider]
		if !ok || len(candidate.digest) != 32 {
			return failure()
		}
		binding, _, err := s.openRPStoredTransaction(ctx, identity.TenantID(candidate.position.tenant), candidate.binding, profile, candidate.position.id, [32]byte(candidate.digest))
		if err != nil || !binding.ExpiresAt.Equal(candidate.position.expires) || !binding.IssuedAt.Equal(candidate.issued) {
			return failure()
		}
		origin, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.Input.binding().CommandID))
		if err != nil || !bytes.Equal(origin, candidate.origin) {
			return failure()
		}
		callback, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.CallbackCommandID))
		if err != nil {
			return failure()
		}
		// This is only a negative exclusion read of the canonical journal owner,
		// never a private replay decision or external-effect inference. Admission
		// locks this same RP row before committing its exchange-start marker
		// (rpLinkPhase.AdmitAccountLinkPreparation). An already-started exchange
		// therefore has a visible claim; a concurrent uncommitted admission must
		// wait for this row and then fail its intact/unexpired-custody predicate.
		// Any claim, including a conflicting/retired one, conservatively excludes
		// erasure. No capability or journal state is changed by maintenance.
		var claimed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$1)`, callback).Scan(&claimed); err != nil {
			return failure()
		}
		if !claimed {
			tag, err := tx.Exec(ctx, `UPDATE `+rpQuotedSchema(s.config().Schema)+`.transactions SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,secrets_erased_at=clock_timestamp(),version=2 WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND secrets_erased_at IS NULL AND expires_at<=clock_timestamp()`, candidate.position.tenant, candidate.position.id)
			if err != nil || tag.RowsAffected() != 1 {
				return failure()
			}
			erased++
		}
	}
	if len(candidates) == maximum {
		next = candidates[len(candidates)-1].position.cursor()
	}
	if err := tx.Commit(ctx); err != nil {
		return failure()
	}
	return erased, next, nil
}

func (p rpExpiryPosition) cursor() string {
	return (url.Values{"expires": {p.expires.UTC().Format(time.RFC3339Nano)}, "tenant": {p.tenant}, "transaction": {p.id}}).Encode()
}

func parseRPExpiryCursor(cursor string) (rpExpiryPosition, error) {
	invalid := identity.InvalidInputError{Field: "oauth_expiry_cursor"}
	if cursor == "" {
		return rpExpiryPosition{expires: time.Unix(0, 0).UTC()}, nil
	}
	if len(cursor) > 1024 || strings.Count(cursor, "&") != 2 {
		return rpExpiryPosition{}, invalid
	}
	fields, err := url.ParseQuery(cursor)
	if err != nil || len(fields) != 3 || len(fields["expires"]) != 1 || len(fields["tenant"]) != 1 || len(fields["transaction"]) != 1 || fields.Encode() != cursor {
		return rpExpiryPosition{}, invalid
	}
	expires, err := time.Parse(time.RFC3339Nano, fields.Get("expires"))
	if err != nil || !rpUTCTime(expires) {
		return rpExpiryPosition{}, invalid
	}
	tenant, transaction := fields.Get("tenant"), fields.Get("transaction")
	if _, err := identity.ParseIdentifierID(tenant); err != nil {
		return rpExpiryPosition{}, invalid
	}
	if _, err := identity.ParseIdentifierID(transaction); err != nil {
		return rpExpiryPosition{}, invalid
	}
	position := rpExpiryPosition{expires: expires, tenant: tenant, id: transaction}
	if position.cursor() != cursor {
		return rpExpiryPosition{}, invalid
	}
	return position, nil
}
