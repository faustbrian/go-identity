package postgres

import (
	"context"

	"github.com/faustbrian/go-identity/delivery"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource extends a complete owned base with immutable delivery schema.
// Base must include the installed identity kernel history; Version must be
// positive and strictly above its final version. Compose with the public
// go-migrations Runner/backend in the same ledger, not a private runner. Install
// the owned outbox schema before admission. Load executes no SQL; zero is invalid.
// Independent Load calls are safe when the borrowed Base supports concurrency.
type MigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
	// WorkerVersion optionally appends the forward delivery-attempt extension.
	// Zero preserves the existing admission-only history; a selected version
	// must be strictly above Version. Neither selection exposes a usable Queue
	// until that adapter's complete authenticated contract is implemented.
	WorkerVersion migrations.Version
	// PolicyVersion optionally appends immutable retained delivery-policy history.
	// It requires WorkerVersion and must be strictly greater. Zero preserves all
	// previously installed migration bytes and does not enable policy registration.
	PolicyVersion migrations.Version
	// KeyedVersion optionally appends original-command request-key mappings.
	// It requires PolicyVersion and must be strictly greater. Zero preserves
	// the installed history and does not expose a complete public Queue.
	KeyedVersion migrations.Version
	// StateVersion optionally appends database-owned monotonic status versions
	// and immutable no-op local-stop checkpoints. It requires KeyedVersion and
	// must be greater. Zero preserves all existing migration bytes/profiles.
	StateVersion migrations.Version
	// CancellationVersion appends immutable original-command cancellation
	// results. It requires StateVersion and must be greater. Zero preserves
	// installed histories; selecting it alone grants no public Queue authority.
	CancellationVersion migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load preserves every original base migration and appends forward-only atomic
// admission and optionally worker migrations. It rejects invalid bases and version
// collisions without changing history. Context cancellation is preserved;
// private source failures are redacted. The returned slice is independently owned.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, delivery.ErrUnavailable
	}
	additional := 1
	if s.WorkerVersion != 0 {
		additional++
		if s.WorkerVersion <= s.Version {
			return nil, delivery.ErrInvalidInput
		}
	}
	if s.PolicyVersion != 0 {
		if s.WorkerVersion == 0 || s.PolicyVersion <= s.WorkerVersion {
			return nil, delivery.ErrInvalidInput
		}
		additional++
	}
	if s.KeyedVersion != 0 {
		if s.PolicyVersion == 0 || s.KeyedVersion <= s.PolicyVersion {
			return nil, delivery.ErrInvalidInput
		}
		additional++
	}
	if s.StateVersion != 0 {
		if s.KeyedVersion == 0 || s.StateVersion <= s.KeyedVersion {
			return nil, delivery.ErrInvalidInput
		}
		additional++
	}
	if s.CancellationVersion != 0 {
		if s.StateVersion == 0 || s.CancellationVersion <= s.StateVersion {
			return nil, delivery.ErrInvalidInput
		}
		additional++
	}
	if len(history) < 1 || len(history)+additional > migrations.MaxMigrationFiles {
		return nil, delivery.ErrInvalidInput
	}
	for n, m := range history {
		if m.Version() == 0 || n > 0 && history[n-1].Version() >= m.Version() {
			return nil, delivery.ErrInvalidInput
		}
	}
	if s.Version <= history[len(history)-1].Version() {
		return nil, delivery.ErrInvalidInput
	}
	last, err := migrations.NewMigration(s.Version, "identity_delivery_intents", migrations.TransactionModeDefault, intentSchemaSQL, "")
	if err != nil {
		return nil, delivery.ErrUnavailable
	}
	result := make([]migrations.Migration, len(history)+additional)
	copy(result, history)
	result[len(history)] = last
	if s.WorkerVersion != 0 {
		worker, err := migrations.NewMigration(s.WorkerVersion, "identity_delivery_attempts", migrations.TransactionModeDefault, attemptSchemaSQL, "")
		if err != nil {
			return nil, delivery.ErrUnavailable
		}
		result[len(history)+1] = worker
	}
	if s.PolicyVersion != 0 {
		policy, err := migrations.NewMigration(s.PolicyVersion, "identity_delivery_policies", migrations.TransactionModeDefault, policySchemaSQL, "")
		if err != nil {
			return nil, delivery.ErrUnavailable
		}
		result[len(history)+2] = policy
	}
	if s.KeyedVersion != 0 {
		keyed, err := migrations.NewMigration(s.KeyedVersion, "identity_delivery_keyed_commands", migrations.TransactionModeDefault, keyedSchemaSQL, "")
		if err != nil {
			return nil, delivery.ErrUnavailable
		}
		result[len(history)+3] = keyed
	}
	if s.StateVersion != 0 {
		state, err := migrations.NewMigration(s.StateVersion, "identity_delivery_status", migrations.TransactionModeDefault, stateSchemaSQL, "")
		if err != nil {
			return nil, delivery.ErrUnavailable
		}
		result[len(history)+4] = state
	}
	if s.CancellationVersion != 0 {
		cancel, err := migrations.NewMigration(s.CancellationVersion, "identity_delivery_cancellations", migrations.TransactionModeDefault, cancellationSchemaSQL, "")
		if err != nil {
			return nil, delivery.ErrUnavailable
		}
		result[len(history)+5] = cancel
	}
	return result, nil
}
