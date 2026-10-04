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
}

var _ migrations.Source = MigrationSource{}

// Load preserves every original base migration and appends one forward-only,
// atomic migration. It rejects absent/unordered/oversized bases and version
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
	if len(history) < 1 || len(history) >= migrations.MaxMigrationFiles {
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
	result := make([]migrations.Migration, len(history)+1)
	copy(result, history)
	result[len(history)] = last
	return result, nil
}
