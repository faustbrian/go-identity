package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	riskpostgres "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource returns this selected store graph's immutable upstream-owned
// histories for the existing go-migrations runner. It performs no IO or apply.
// Kernel versions remain 1..9; reference reserves 1000..1011 permanently for
// the velocity authority chain. Existing adapter deployments using other
// allocations are not silently adopted. This partial development profile does
// not implement the complete reference Check/Plan/Apply migration coordinator.
func (s StoreSet) MigrationSource() migrations.Source {
	return storeMigrationSource{state: s.state}
}

type storeMigrationSource struct{ state *storeState }

func (s storeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.state == nil {
		return nil, identity.InvalidInputError{Field: "reference_stores"}
	}
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	base := riskpostgres.MigrationSource{Schema: s.state.config.Schema, Version: 1000}
	issued := riskpostgres.IssuanceIDMigrationSource{Base: base, Version: 1001}
	reserved := riskpostgres.ReservationMigrationSource{Base: issued, Version: 1002}
	counter := riskpostgres.CounterMigrationSource{Base: reserved, Version: 1003}
	journal := riskpostgres.VelocityMigrationSource{Base: counter, Version: 1004}
	intent := riskpostgres.VelocityIntentMigrationSource{Base: journal, Version: 1005}
	integrity := riskpostgres.VelocityIntegrityMigrationSource{Base: intent, Version: 1006}
	replay := riskpostgres.VelocityReplayMigrationSource{Base: integrity, Version: 1007}
	applied := riskpostgres.VelocityAppliedMigrationSource{Base: replay, Version: 1008}
	coverage := riskpostgres.VelocityCoverageMigrationSource{Base: applied, Version: 1009}
	publication := riskpostgres.VelocityPublicationMigrationSource{Base: coverage, Version: 1010}
	history, err := (riskpostgres.VelocityActivationMigrationSource{Base: publication, Version: 1011}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(kernel, history...), nil
}
