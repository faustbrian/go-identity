package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// RequestKeyExpiryContributor restores the exact authenticated original binding
// and exclusive preparation deadline without refreshing any authority or input.
// The deadline is the earliest original preparation/session validity ceiling,
// never reconstructed from the current clock or a replacement session. The
// native codec must authenticate the complete RequestKeyPreparationBinding and
// immutable configuration alongside it. Like RestoreRequestKey, this is bounded
// pure decoding outside SQL: no callbacks, generation, counters or side effects.
type RequestKeyExpiryContributor interface {
	RequestKeyRecoveryContributor
	RestoreRequestKeyExpiry(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, time.Time, error)
}

// ExpirePreparedFeatureCommand resolves an abandoned exact mapped origin after
// its immutable preparation deadline. Definitive noncommit requires a permanent
// global command-ID fence; mere absence or elapsed time never proves rollback.
// Existing commands remain under the ordinary recovery owner, never retirement.
// Install RequestKeyExpiryMigrationSource before selecting this API. The exact
// registered native codec and current query policy control disclosure. Before
// expiry, an absent claim remains Unknown. Concurrent original reservation wins
// or loses through the existing global primary key; it is never overwritten.
// A matching retained fence returns metadata-only NotCommitted and prevents
// every subsequent reservation of that ID. It cannot permit retrying effects.
// Generic recovery and ordinary retired-row privacy remain unchanged. Lost
// commit acknowledgement returns Unknown; retry this exact origin. The pool is
// borrowed, calls are bounded/concurrent and no goroutine or callback runs in SQL.
func (c *Coordinator) ExpirePreparedFeatureCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyExpiryContributor) (identity.CommandResult, error) {
	if c == nil || ctx == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return identity.CommandResult{}, coordinatorError()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	input, wire, err := c.queryRequestPreparation(ctx, q, caller, feature, owner, true)
	defer clear(wire)
	if err != nil {
		return identity.CommandResult{}, err
	}
	original, deadline, err := restoreRequestKeyExpiry(ctx, owner, input, wire)
	if err != nil {
		return identity.CommandResult{}, err
	}
	unknown := featureOutcome(original, &feature.Operation, identity.CommitOutcomeUnknown, 0)
	if original.CommandID != input.Admission.CommandID || original.TenantID != input.Scope.TenantID || original.ActorID != input.Scope.ActorID || original.ActorKind != input.Scope.ActorKind || original.OperationID != input.Scope.RouteID || original.SchemaID != feature.Operation.SchemaID || original.SchemaVersion != feature.Operation.SchemaVersion || unknown.Validate() != nil || !requestRecoveryScope(q, original) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	exclusive, err := requestKeyExpiryDeadline(deadline)
	if err != nil {
		return identity.CommandResult{}, err
	}
	allowed, err := c.authorizeCommandQuery(ctx, q, caller)
	if err != nil {
		return identity.CommandResult{}, err
	}
	if !allowed {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	origin := c.requestKeyExpiryFingerprint(input, original, deadline, wire)
	begin := c.pool.Raw().Begin
	if c.requestKeyBegin != nil {
		begin = c.requestKeyBegin
	}
	tx, err := begin(ctx)
	if err != nil {
		return identity.CommandResult{}, readFailure(ctx, err)
	}
	defer rollbackList(tx, c.maximumDuration)
	raw, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	// Unique-key arbitration serializes this irreversible refusal with every
	// normal and prepared command claimant. Never update an existing claim.
	inserted, err := tx.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,retired,request_key_expiry_fingerprint)
SELECT $1,true,$2 WHERE clock_timestamp()>=$3 ON CONFLICT DO NOTHING`, raw, origin[:], exclusive)
	if err != nil {
		return identity.CommandResult{}, readFailure(ctx, err)
	}
	var retired bool
	var retained []byte
	err = tx.QueryRow(ctx, `SELECT retired,request_key_expiry_fingerprint FROM identity.identity_command_id_claims WHERE command_id=$1 FOR UPDATE`, raw).Scan(&retired, &retained)
	if errors.Is(err, pgx.ErrNoRows) {
		return unknown, identity.UnknownCommitError{CommandID: original.CommandID}
	}
	if err != nil {
		return identity.CommandResult{}, readFailure(ctx, err)
	}
	if !retired {
		// Normal reconciliation must not run while this observation holds the
		// global claim lock. It authenticates the complete original again.
		if err := tx.Rollback(ctx); err != nil {
			return unknown, identity.UnknownCommitError{CommandID: original.CommandID}
		}
		return c.RecoverPreparedFeatureCommand(ctx, q, caller, feature, owner)
	}
	if len(retained) != len(origin) || !hmac.Equal(retained, origin[:]) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	if inserted.RowsAffected() == 1 {
		// Arbitration may have waited for a competing insertion to roll back.
		// Recheck the primary clock under the winning lock before committing
		// a new refusal; an existing committed refusal never becomes live again.
		var expired bool
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()>=$1`, exclusive).Scan(&expired); err != nil {
			return identity.CommandResult{}, readFailure(ctx, err)
		}
		if !expired {
			return unknown, identity.UnknownCommitError{CommandID: original.CommandID}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return unknown, identity.UnknownCommitError{CommandID: original.CommandID}
	}
	return featureOutcome(original, &feature.Operation, identity.CommitOutcomeNotCommitted, 0), nil
}

func requestKeyExpiryDeadline(deadline time.Time) (time.Time, error) {
	// PostgreSQL timestamps have microsecond resolution. Round up, never down:
	// loss of sub-microsecond precision cannot retire a still-valid origin.
	exclusive := deadline.UTC().Truncate(time.Microsecond)
	if exclusive.Before(deadline) {
		exclusive = exclusive.Add(time.Microsecond)
	}
	if deadline.IsZero() || !postgresExactTime(exclusive) {
		return time.Time{}, identity.UnavailableError{}
	}
	return exclusive, nil
}

func (c *Coordinator) requestKeyExpiryFingerprint(input RequestKeyPreparationBinding, b identity.CommandBinding, deadline time.Time, wire []byte) [32]byte {
	native := sha256.Sum256(wire)
	feature := requestPreparationIdentity(input.Feature)
	canonical := cborMap(map[string][]byte{
		"profile":   cborText("identity-request-key-expiry-v1"),
		"namespace": cborText(input.Namespace), "tenant": cborText(string(input.Scope.TenantID)),
		"actor": cborText(string(input.Scope.ActorID)), "actor_kind": cborText(string(input.Scope.ActorKind)),
		"method": cborText(input.Scope.Method), "route": cborText(input.Scope.RouteID),
		"policy": cborUint(input.PolicyVersion), "key_version": cborUint(uint64(input.Admission.FingerprintKeyVersion)),
		"command_scope": cborBytes(commandSafeFields(b, &input.Feature.Operation)),
		"feature":       cborBytes(feature[:]), "intent": cborBytes(input.IntentDigest[:]),
		"native": cborBytes(native[:]), "deadline": cborText(deadline.UTC().Format(time.RFC3339Nano)),
	})
	defer clear(canonical)
	return claimFingerprint(c.keys.retained[input.Admission.FingerprintKeyVersion], canonical)
}

func restoreRequestKeyExpiry(ctx context.Context, owner RequestKeyExpiryContributor, input RequestKeyPreparationBinding, wire []byte) (binding identity.CommandBinding, deadline time.Time, err error) {
	defer func() {
		if recover() != nil {
			binding, deadline, err = identity.CommandBinding{}, time.Time{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			binding, deadline, err = identity.CommandBinding{}, time.Time{}, readFailure(ctx, ctx.Err())
		}
	}()
	if ctx.Err() != nil {
		return binding, deadline, readFailure(ctx, ctx.Err())
	}
	binding, deadline, err = owner.RestoreRequestKeyExpiry(ctx, input, wire)
	if err != nil {
		return identity.CommandBinding{}, time.Time{}, identity.UnavailableError{}
	}
	return binding, deadline, nil
}
