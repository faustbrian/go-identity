package reference

import (
	"context"
	"errors"
	"slices"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// ModuleID identifies a selected canonical migration owner, not a database or
// ledger name. Unknown, unselected, duplicate and empty IDs are invalid.
type ModuleID string

// MigrationCompatibility is the closed relationship between an owned source
// and its authoritative native history. Zero is invalid.
type MigrationCompatibility uint8

const (
	// MigrationCompatible means every required step is clean and identity-matched.
	MigrationCompatible MigrationCompatibility = iota + 1
	// MigrationRequired means an original forward suffix is not installed.
	MigrationRequired
	// MigrationIncompatible means history drift or unmanaged owned objects.
	MigrationIncompatible
	// MigrationDirty means a recognized step has an unresolved native outcome.
	MigrationDirty
)

// ModuleMigrationStatus contains only public owner/version metadata. It is a
// discovery snapshot, not permission to apply or a guarantee of future health.
// Versions are maxima across selected native histories. Compatibility, not
// numeric equality, establishes completeness of a multi-history owner.
type ModuleMigrationStatus struct {
	Module          string
	CurrentVersion  uint64
	RequiredVersion uint64
	Compatibility   MigrationCompatibility
}

// ReferenceMigrationCheckRequest selects 1..128 unique canonical module IDs,
// each at most 128 bytes. Current versions are never supplied by the caller.
type ReferenceMigrationCheckRequest struct{ Modules []ModuleID }

// ReferenceMigrationCheckResult returns independently owned statuses sorted by
// canonical module ID. Different ledgers are separately discovered snapshots.
type ReferenceMigrationCheckResult struct{ Statuses []ModuleMigrationStatus }

// ReferenceMigrationCheck discovers selected native histories without preparing
// ledgers, acquiring apply locks, migrating, baselining or initializing features.
// Each requested owner's complete physical history participates in validation,
// including shared-ledger prerequisites; only requested statuses are returned. Missing history
// with owned objects is incompatible, never permission for silent adoption.
//
// One PrimaryTimeout bounds the whole check. Calls are concurrent-safe and
// join the store lifetime: Close cancels/drains them. The borrowed PostgreSQL
// pool remains open. Invalid inputs, cancellation and dependency failures return
// no partial statuses; errors redact database diagnostics. A discovered dirty
// or incompatible history returns explicit status, not healthy readiness.
// This store operation supports the future ReferenceService/server facade; it
// does not implement the complete service, Apply or command recovery.
func (s StoreSet) ReferenceMigrationCheck(ctx context.Context, req ReferenceMigrationCheckRequest) (ReferenceMigrationCheckResult, error) {
	bounded, ids, finish, err := s.beginMigrationOperation(ctx, req.Modules)
	if err != nil {
		return ReferenceMigrationCheckResult{}, err
	}
	defer finish()
	snapshots, err := s.discoverMigrations(bounded, ids)
	if err != nil {
		return ReferenceMigrationCheckResult{}, err
	}
	statuses := make(map[ModuleID]ModuleMigrationStatus)
	for _, snapshot := range snapshots {
		for owner, status := range snapshot.statuses {
			statuses[owner] = mergeMigrationStatus(statuses[owner], status)
		}
	}
	result := ReferenceMigrationCheckResult{Statuses: make([]ModuleMigrationStatus, 0, len(ids))}
	for _, id := range ids {
		result.Statuses = append(result.Statuses, statuses[id])
	}
	if err := bounded.Err(); err != nil {
		return ReferenceMigrationCheckResult{}, err
	}
	return result, nil
}

func mergeMigrationStatus(a, b ModuleMigrationStatus) ModuleMigrationStatus {
	return ModuleMigrationStatus{Module: b.Module, CurrentVersion: max(a.CurrentVersion, b.CurrentVersion), RequiredVersion: max(a.RequiredVersion, b.RequiredVersion), Compatibility: max(a.Compatibility, b.Compatibility)}
}

// Check and Plan share one discovery/lifetime boundary. Returned snapshots are
// operation-local; they never authorize writes or survive into stored authority.
type migrationSnapshot struct {
	history  migrationHistory
	records  []migrations.Record
	statuses map[ModuleID]ModuleMigrationStatus
}

func (s StoreSet) beginMigrationOperation(ctx context.Context, modules []ModuleID) (context.Context, []ModuleID, func(), error) {
	if ctx == nil || s.state == nil || len(modules) == 0 || len(modules) > 128 {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_migrations"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	ids := slices.Clone(modules)
	slices.Sort(ids)
	for i, id := range ids {
		if len(id) == 0 || len(id) > 128 || i > 0 && ids[i-1] == id {
			return nil, nil, nil, identity.InvalidInputError{Field: "reference_modules"}
		}
	}
	state := s.state
	state.mu.Lock()
	if state.closed || state.pool == nil || state.pool.Raw() == nil {
		state.mu.Unlock()
		return nil, nil, nil, identity.UnavailableError{}
	}
	if state.active == 0 {
		state.drained = make(chan struct{})
	}
	state.active++
	state.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, state.config.PrimaryTimeout)
	stop := context.AfterFunc(state.lifetime, cancel)
	finish := func() {
		stop()
		cancel()
		state.mu.Lock()
		state.active--
		if state.active == 0 {
			close(state.drained)
		}
		state.mu.Unlock()
	}
	return bounded, ids, finish, nil
}

func (s StoreSet) discoverMigrations(ctx context.Context, ids []ModuleID) ([]migrationSnapshot, error) {
	catalog, err := s.migrationCatalog(ctx)
	if err != nil {
		return nil, checkFailure(ctx, err)
	}
	selected := make(map[ModuleID]bool)
	for _, h := range catalog {
		for _, owner := range h.owners {
			selected[owner] = true
		}
	}
	for _, id := range ids {
		if !selected[id] {
			return nil, identity.InvalidInputError{Field: "reference_modules"}
		}
	}
	// The bridge is operation-owned, not a construction-time goroutine/resource.
	// Closing it releases connections, never the borrowed pgx pool.
	db := stdlib.OpenDBFromPool(s.state.pool.Raw())
	defer db.Close()
	db.SetMaxOpenConns(1)
	backend, err := migrationdb.New(db)
	if err != nil {
		return nil, checkFailure(ctx, err)
	}
	snapshots := make([]migrationSnapshot, 0, len(catalog))
	for _, h := range catalog {
		requested := false
		for _, id := range ids {
			for _, owner := range h.owners {
				requested = requested || id == owner
			}
		}
		if !requested {
			continue
		}
		owned := backend
		if h.namespace != "" {
			owned, err = backend.ForNamespace(h.namespace)
			if err != nil {
				return nil, checkFailure(ctx, err)
			}
		}
		records, readErr := owned.ReadLedger(ctx)
		foreign := errors.Is(readErr, migrationdb.ErrLedgerConflict)
		if readErr != nil && !foreign {
			return nil, checkFailure(ctx, readErr)
		}
		projection := h.project(records)
		unmanaged := false
		for _, guard := range h.guards {
			if _, selected := h.owners[guard.version]; !selected {
				continue
			}
			applied := false
			for _, r := range records {
				if r.Version() == guard.version {
					applied = true
					break
				}
			}
			if !applied {
				exists, err := guard.exists(ctx, s.state)
				if err != nil {
					return nil, checkFailure(ctx, err)
				}
				unmanaged = unmanaged || exists
			}
		}
		for owner, status := range projection {
			if foreign || unmanaged {
				status.Compatibility = MigrationIncompatible
			}
			projection[owner] = status
		}
		snapshots = append(snapshots, migrationSnapshot{history: h, records: records, statuses: projection})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snapshots, nil
}

func checkFailure(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.UnavailableError{}
}

func (h migrationHistory) project(records []migrations.Record) map[ModuleID]ModuleMigrationStatus {
	result := make(map[ModuleID]ModuleMigrationStatus)
	for _, step := range h.history {
		owner := h.owners[step.Version()]
		status := result[owner]
		status.Module = string(owner)
		status.RequiredVersion = uint64(step.Version())
		status.Compatibility = MigrationCompatible
		result[owner] = status
	}
	for _, record := range records {
		if owner, ok := h.owners[record.Version()]; ok {
			status := result[owner]
			status.CurrentVersion = uint64(record.Version())
			result[owner] = status
		}
	}
	status, err := migrations.BuildStatus(h.history, records)
	if err != nil {
		for owner, item := range result {
			item.Compatibility = MigrationIncompatible
			result[owner] = item
		}
		return result
	}
	dirty := false
	for _, entry := range status.Entries() {
		if entry.State() == migrations.StateDirty {
			dirty = true
		}
		if entry.State() == migrations.StatePending {
			owner := h.owners[entry.Version()]
			item := result[owner]
			item.Compatibility = MigrationRequired
			result[owner] = item
		}
	}
	if dirty {
		for owner, item := range result {
			item.Compatibility = MigrationDirty
			result[owner] = item
		}
	}
	return result
}
