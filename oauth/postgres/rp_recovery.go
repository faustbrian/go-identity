package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"

	identity "github.com/faustbrian/go-identity"
)

// RecoverExpiredAttached reconciles abandoned explicit-link callbacks after
// their original RP window expires. This trusted backend operation authenticates
// retained metadata and uses the existing coordinator's historical recovery; it
// does not accept browser custody, restore a live Grant, exchange or issue access.
// Ordinary expired callbacks remain forbidden. Unattached or uncertain exchanges
// retain their reservations and ciphertext. Retain the original provider/key
// configuration until its custody is drained.
//
// maximum bounds examined tenant-owned rows to 1..100. Empty cursor starts a
// sweep; a nonempty returned cursor resumes it. Recovered counts acknowledged
// noncommit observations, not exactly-once erasures. Concurrent sweepers can
// observe the same terminal result. Each candidate settles in its own canonical
// transaction; on error, prior counts and the last completed cursor remain valid.
// No RP row lock is held while entering the coordinator's claim-first lock order.
// The caller owns scheduling/pool lifetime; no goroutine or timer is started.
func (s *LinkService) RecoverExpiredAttached(ctx context.Context, tenant identity.TenantID, maximum int, cursor string) (recovered int, next string, err error) {
	invalid := identity.InvalidInputError{Field: "oauth_recovery"}
	if s == nil || s.pool == nil || s.pool.Raw() == nil || s.config == nil || ctx == nil || maximum < 1 || maximum > 100 {
		return 0, "", invalid
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return 0, "", invalid
	}
	after, err := parseRPExpiryCursor(cursor)
	if err != nil || cursor != "" && after.tenant != string(tenant) {
		return 0, "", invalid
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	rows, err := s.pool.Raw().Query(ctx, `SELECT expires_at,tenant_id,transaction_id,provider_id,origin_command_id,state_digest,binding_ciphertext,issued_at
 FROM `+rpQuotedSchema(s.config().Schema)+`.transactions
 WHERE tenant_id=$1 AND operation='identity.account.link-start' AND version=1 AND secrets_erased_at IS NULL
 AND expires_at<=clock_timestamp() AND (expires_at,transaction_id)>($2,$3)
 ORDER BY expires_at,transaction_id LIMIT $4`, string(tenant), after.expires, after.id, maximum)
	if err != nil {
		return 0, "", identity.UnavailableError{}
	}
	defer rows.Close()
	candidates := make([]rpExpiredTransaction, 0, maximum)
	for rows.Next() {
		var candidate rpExpiredTransaction
		if rows.Scan(&candidate.position.expires, &candidate.position.tenant, &candidate.position.id, &candidate.provider, &candidate.origin, &candidate.digest, &candidate.binding, &candidate.issued) != nil || len(candidates) >= maximum {
			return 0, "", identity.UnavailableError{}
		}
		candidates = append(candidates, candidate)
	}
	if rows.Err() != nil {
		return 0, "", identity.UnavailableError{}
	}
	rows.Close()
	for _, candidate := range candidates {
		flow, failure := s.expiredRecoveryFlow(ctx, candidate)
		if failure != nil {
			return recovered, next, failure
		}
		spec, failure := callbackSpecification(flow)
		if failure != nil {
			return recovered, next, failure
		}
		b := spec.Binding
		result, handled, failure := s.recoverExpiredProviderFailure(ctx, flow)
		if failure != nil {
			var forbidden identity.ForbiddenError
			if !errors.As(failure, &forbidden) {
				return recovered, next, failure
			}
			// Missing or foreign claims grant no cleanup authority. Only the
			// canonical owner decides whether an attached plan can settle.
			next = candidate.position.cursor()
			continue
		}
		if !handled {
			next = candidate.position.cursor()
			continue
		}
		if result.Binding.OperationID == rpDenialOperation().OperationID {
			b = (&rpDenialPhase{service: s, flow: flow}).historicalBinding()
		}
		if result.Binding != b {
			return recovered, next, identity.UnavailableError{}
		}
		if result.Outcome == identity.CommitOutcomeNotCommitted {
			var erased bool
			if failure := s.pool.Raw().QueryRow(ctx, `SELECT version=2 AND secrets_erased_at IS NOT NULL AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL FROM `+rpQuotedSchema(s.config().Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3`, string(tenant), candidate.position.id, candidate.origin).Scan(&erased); failure != nil || !erased {
				return recovered, next, identity.UnavailableError{}
			}
			recovered++
		}
		next = candidate.position.cursor()
	}
	if len(candidates) < maximum {
		next = ""
	}
	return recovered, next, nil
}

// Retained AEAD metadata supplies historical correlation, never a usable state
// proof or current session. Recovery rechecks its exact state/row under the
// existing coordinator locks before erasure and canonical proof release.
func (s *LinkService) expiredRecoveryFlow(ctx context.Context, candidate rpExpiredTransaction) (rpCallbackFlow, error) {
	profile, ok := s.profiles[candidate.provider]
	if !ok || len(candidate.digest) != 32 || len(candidate.origin) != 16 {
		return rpCallbackFlow{}, identity.UnavailableError{}
	}
	binding, state, err := s.openRPStoredTransaction(ctx, identity.TenantID(candidate.position.tenant), candidate.binding, profile, candidate.position.id, [32]byte(candidate.digest))
	if err != nil || !binding.ExpiresAt.Equal(candidate.position.expires) || !binding.IssuedAt.Equal(candidate.issued) {
		return rpCallbackFlow{}, identity.UnavailableError{}
	}
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.Input.binding().CommandID))
	if err != nil || !bytes.Equal(origin, candidate.origin) {
		return rpCallbackFlow{}, identity.UnavailableError{}
	}
	original, err := (&rpStartPhase{service: s, input: &binding.Input}).originalSession()
	if err != nil {
		return rpCallbackFlow{}, err
	}
	return rpCallbackFlow{binding: binding, statePlan: state, original: original}, nil
}
