package reference

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ModuleVersion is an authoritative current version, including zero for an
// empty owner history. It is never a caller-supplied planning target.
type ModuleVersion struct {
	Module  string
	Version uint64
}

// MigrationStep identifies one native forward migration without exposing SQL.
// FromVersion is the owner's preceding version, not another owner's version in
// a shared ledger. SourceDigest binds the complete participating physical source.
type MigrationStep struct {
	Owner        ModuleID
	ID           string
	FromVersion  uint64
	ToVersion    uint64
	SourceDigest [32]byte
	StepDigest   [32]byte
}

// MigrationPlan is a detached canonical snapshot, not execution authority.
// Modules and Steps are caller-owned copies. Treat the value as immutable;
// changing any field invalidates Digest. Apply must independently rediscover
// and validate the complete value before writes. A nonzero digest with no steps
// represents a valid no-op; the zero value is invalid.
type MigrationPlan struct {
	BaseLedgerDigest [32]byte
	CatalogDigest    [32]byte
	Modules          []ModuleVersion
	Steps            []MigrationStep
	Digest           [32]byte
}

// ReferenceMigrationPlanRequest selects 1..128 unique selected canonical IDs.
// Pending prerequisites must be explicitly selected; completed prerequisites
// are discovered, never supplied or silently reapplied by the caller.
type ReferenceMigrationPlanRequest struct{ Modules []ModuleID }

// ReferenceMigrationPlanResult contains one detached complete canonical plan.
type ReferenceMigrationPlanResult struct{ Plan MigrationPlan }

// ReferenceMigrationPlan plans native migration work without preparing ledgers,
// acquiring apply ownership or changing schema. It is bounded by PrimaryTimeout
// and the store lifetime. This operation does not implement Apply or recovery.
func (s StoreSet) ReferenceMigrationPlan(ctx context.Context, req ReferenceMigrationPlanRequest) (ReferenceMigrationPlanResult, error) {
	bounded, ids, finish, err := s.beginMigrationOperation(ctx, req.Modules)
	if err != nil {
		return ReferenceMigrationPlanResult{}, err
	}
	defer finish()
	discovery := slices.Clone(ids)
	if slices.Contains(ids, ModuleID("outbox/postgres/identity")) && !slices.Contains(ids, ModuleID("outbox/postgres")) {
		discovery = append(discovery, "outbox/postgres")
	}
	snapshots, err := s.discoverMigrations(bounded, discovery)
	if err != nil {
		return ReferenceMigrationPlanResult{}, err
	}
	plan, err := buildMigrationPlan(snapshots, ids)
	if err != nil {
		return ReferenceMigrationPlanResult{}, err
	}
	if err := bounded.Err(); err != nil {
		return ReferenceMigrationPlanResult{}, err
	}
	return ReferenceMigrationPlanResult{Plan: plan}, nil
}

// Discovery is not a global transaction: Apply must reacquire ownership and
// rediscover every contributing ledger. Never retain this value as authority.
func buildMigrationPlan(snapshots []migrationSnapshot, ids []ModuleID) (MigrationPlan, error) {
	plan := MigrationPlan{Modules: make([]ModuleVersion, 0, len(ids))}
	selected := make(map[ModuleID]bool, len(ids))
	current := make(map[ModuleID]uint64)
	for _, id := range ids {
		selected[id] = true
	}
	for _, snapshot := range snapshots {
		for owner, status := range snapshot.statuses {
			if status.Compatibility != MigrationCompatible && status.Compatibility != MigrationRequired {
				return MigrationPlan{}, identity.ConflictError{}
			}
			current[owner] = status.CurrentVersion
			// Lifecycle bindings cannot be installed before the root outbox,
			// even though the two owners have independent native namespaces.
			if owner == "outbox/postgres" && selected["outbox/postgres/identity"] && !selected[owner] && status.Compatibility != MigrationCompatible {
				return MigrationPlan{}, identity.ConflictError{}
			}
		}
	}
	for _, id := range ids {
		plan.Modules = append(plan.Modules, ModuleVersion{Module: string(id), Version: current[id]})
	}
	catalog, ledger := newMigrationDigest("catalog"), newMigrationDigest("ledger")
	catalog.number(uint64(len(snapshots)))
	ledger.number(uint64(len(snapshots)))
	for _, snapshot := range snapshots {
		h := snapshot.history
		sourceDigest := migrationSourceDigest(h)
		catalog.string(h.namespace)
		catalog.digest(sourceDigest)
		ledger.string(h.namespace)
		ledger.number(uint64(len(snapshot.records)))
		for _, r := range snapshot.records {
			ledger.number(uint64(r.Kind()))
			ledger.number(uint64(r.Version()))
			ledger.string(r.Name())
			ledger.string(r.Checksum().String())
			ledger.string(r.AppliedAt().UTC().Format(time.RFC3339Nano))
			ledger.number(uint64(r.Duration()))
			if r.Dirty() {
				ledger.number(1)
			} else {
				ledger.number(0)
			}
		}
		native, err := migrations.PlanUp(h.history, snapshot.records)
		if err != nil {
			return MigrationPlan{}, identity.ConflictError{}
		}
		pending := native.Steps()
		last := -1
		for i, step := range pending {
			if selected[h.owners[step.Migration().Version()]] {
				last = i
			}
		}
		if last+1 > 4096-len(plan.Steps) {
			return MigrationPlan{}, identity.InvalidInputError{Field: "reference_plan_steps"}
		}
		for _, item := range pending[:last+1] {
			m := item.Migration()
			owner := h.owners[m.Version()]
			if !selected[owner] {
				return MigrationPlan{}, identity.ConflictError{}
			}
			id := strconv.FormatUint(uint64(m.Version()), 10) + "_" + m.Name()
			if len(id) > 128 {
				return MigrationPlan{}, identity.InvalidInputError{Field: "reference_plan_step_id"}
			}
			step := MigrationStep{Owner: owner, ID: id, FromVersion: current[owner], ToVersion: uint64(m.Version()), SourceDigest: sourceDigest}
			step.StepDigest = migrationStepDigest(step)
			plan.Steps = append(plan.Steps, step)
			current[owner] = step.ToVersion
		}
	}
	plan.CatalogDigest, plan.BaseLedgerDigest = catalog.sum(), ledger.sum()
	plan.Digest = migrationPlanDigest(plan)
	return plan, nil
}

// V1 encoding uses domain-separated SHA-256, big-endian uint64 counts and
// length-prefixed strings. No SQL, wall clock or connection identity escapes.
type migrationDigest struct{ hash.Hash }

func newMigrationDigest(domain string) migrationDigest {
	d := migrationDigest{sha256.New()}
	d.string("golib/reference/migrations/v1/" + domain)
	return d
}

func (d migrationDigest) number(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	_, _ = d.Write(b[:])
}

func (d migrationDigest) string(s string) {
	d.number(uint64(len(s)))
	_, _ = d.Write([]byte(s))
}

func (d migrationDigest) digest(v [32]byte) { _, _ = d.Write(v[:]) }

func (d migrationDigest) sum() [32]byte { return [32]byte(d.Sum(nil)) }

func migrationSourceDigest(h migrationHistory) [32]byte {
	d := newMigrationDigest("source")
	d.string(h.namespace)
	d.string(h.preflight)
	d.number(uint64(len(h.history)))
	for _, m := range h.history {
		d.number(uint64(m.Version()))
		d.string(m.Name())
		d.number(uint64(m.TransactionMode()))
		d.string(m.Checksum().String())
		d.string(string(h.owners[m.Version()]))
	}
	guards := make([]migrationGuard, 0, len(h.guards))
	for _, guard := range h.guards {
		if _, ok := h.owners[guard.version]; ok {
			guards = append(guards, guard)
		}
	}
	d.number(uint64(len(guards)))
	for _, g := range guards {
		d.number(uint64(g.version))
		d.string(g.schema)
		for _, names := range [][]string{g.tables, g.roles, g.columns, g.functions} {
			d.number(uint64(len(names)))
			for _, name := range names {
				d.string(name)
			}
		}
	}
	return d.sum()
}

func migrationStepDigest(step MigrationStep) [32]byte {
	d := newMigrationDigest("step")
	writeMigrationStep(d, step)
	return d.sum()
}

func writeMigrationStep(d migrationDigest, step MigrationStep) {
	d.string(string(step.Owner))
	d.string(step.ID)
	d.number(step.FromVersion)
	d.number(step.ToVersion)
	d.digest(step.SourceDigest)
}

func migrationPlanDigest(plan MigrationPlan) [32]byte {
	d := newMigrationDigest("plan")
	d.digest(plan.BaseLedgerDigest)
	d.digest(plan.CatalogDigest)
	d.number(uint64(len(plan.Modules)))
	for _, module := range plan.Modules {
		d.string(module.Module)
		d.number(module.Version)
	}
	d.number(uint64(len(plan.Steps)))
	for _, step := range plan.Steps {
		writeMigrationStep(d, step)
		d.digest(step.StepDigest)
	}
	return d.sum()
}
