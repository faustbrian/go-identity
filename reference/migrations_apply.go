package reference

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// MigrationApplyPolicy enables explicit offline operator migrations. Scope and
// LookupKey are trusted deployment inputs, not request-supplied authorization.
// LookupKey is a nonzero stable secret retained across retries/reconstruction;
// replacing it cannot rebind an existing command. Native command records must
// remain retained while resume/reconciliation is possible (no automatic TTL).
// LockTimeout defaults to 30s; explicit values are 1s..5m. CleanupTimeout is
// positive and at most one minute. PrimaryTimeout bounds the entire operation,
// independently of the lock budget. Construction copies this value; callers
// must not mutate input concurrently. Diagnostic projections redact the key.
type MigrationApplyPolicy struct {
	TenantID       identity.TenantID
	ActorID        identity.ActorID
	LookupKey      [32]byte
	LockTimeout    time.Duration
	CleanupTimeout time.Duration
}

// String redacts operator policy and secret custody.
func (MigrationApplyPolicy) String() string { return "[migration apply policy]" }

// GoString redacts operator policy and secret custody.
func (p MigrationApplyPolicy) GoString() string { return p.String() }

// Format redacts every formatting verb, including structural diagnostics.
func (p MigrationApplyPolicy) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(p.String())) }

// MarshalJSON deliberately exports no operator scope or key.
func (MigrationApplyPolicy) MarshalJSON() ([]byte, error) {
	return []byte(`"[migration apply policy]"`), nil
}

// LogValue deliberately exports no operator scope or key.
func (p MigrationApplyPolicy) LogValue() slog.Value { return slog.StringValue(p.String()) }

func copyMigrationApplyPolicy(input *MigrationApplyPolicy) (*MigrationApplyPolicy, error) {
	if input == nil {
		return nil, nil
	}
	p := *input
	if p.LockTimeout == 0 {
		p.LockTimeout = 30 * time.Second
	}
	if !migrationScope(string(p.TenantID)) || !migrationScope(string(p.ActorID)) || p.LookupKey == [32]byte{} || p.LockTimeout < time.Second || p.LockTimeout > 5*time.Minute || p.CleanupTimeout <= 0 || p.CleanupTimeout > time.Minute {
		return nil, identity.InvalidInputError{Field: "reference_migration_policy"}
	}
	return &p, nil
}

func migrationScope(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ReferenceMigrationApplyRequest supplies the complete immutable original plan,
// a globally unique command ID and an owned retry key. This operation's command
// grammar is 16..128 ASCII letters, digits, underscore or hyphen (not the kernel
// command generator's narrower encoding). Concurrent input mutation is invalid.
type ReferenceMigrationApplyRequest struct {
	CommandID      identity.CommandID
	Plan           MigrationPlan
	IdempotencyKey identity.IdempotencyKey
}

// MigrationApplyState is a closed execution/recovery classification. Zero is
// invalid, not success. Pending may contain a durable prefix; only Applied
// means the complete original plan has native attribution and current validity.
type MigrationApplyState uint8

const (
	// MigrationApplied means all selected batches are durably attributed.
	MigrationApplied MigrationApplyState = iota + 1
	// MigrationApplyPending means an incomplete command can be retried exactly.
	MigrationApplyPending
	// MigrationApplyDirty denies execution until explicit native recovery.
	MigrationApplyDirty
	// MigrationApplyIncompatible denies drift, unowned state or changed plans.
	MigrationApplyIncompatible
	// MigrationApplyLocked means bounded ownership acquisition timed out.
	MigrationApplyLocked
	// MigrationApplyUnknown requires authoritative same-command reconciliation.
	MigrationApplyUnknown
)

// MigrationContributorReceipt is public progress metadata, never execution
// authority. Version is the maximum command-attributed original native version
// across this owner's participating histories, not a merged sequence. Native
// namespace-qualified receipts remain authority. No private digest escapes.
type MigrationContributorReceipt struct {
	Module  ModuleID
	Version uint64
}

// MigrationApplyResult is an immutable public projection of native authority.
// Copies share no mutable slices with the owner; zero is invalid. At most 128
// sorted owner receipts are returned. It cannot authorize resume by itself.
type MigrationApplyResult struct {
	command  identity.CommandID
	digest   [32]byte
	state    MigrationApplyState
	receipts []MigrationContributorReceipt
}

// CommandID returns the original stable command, including unknown outcomes.
func (r MigrationApplyResult) CommandID() identity.CommandID { return r.command }

// Digest returns the bound complete original plan digest.
func (r MigrationApplyResult) Digest() [32]byte { return r.digest }

// State returns the execution/reconciliation classification; zero is invalid.
func (r MigrationApplyResult) State() MigrationApplyState { return r.state }

// Receipts returns detached sorted command-attributed contributor progress.
func (r MigrationApplyResult) Receipts() []MigrationContributorReceipt {
	return slices.Clone(r.receipts)
}

// ReferenceMigrationApplyResult contains one immutable bounded projection.
type ReferenceMigrationApplyResult struct{ Result MigrationApplyResult }

// MigrationError preserves migration state and a safe identity/context error.
// Driver diagnostics never cross this boundary. Unknown always unwraps to the
// original identity.UnknownCommitError, never inferred success or rollback.
type MigrationError struct {
	state MigrationApplyState
	cause error
}

// Error returns only a stable diagnostic without database/provider payloads.
func (MigrationError) Error() string { return "reference migration apply failed" }

// State returns the distinguished migration failure class.
func (e MigrationError) State() MigrationApplyState { return e.state }

// Unwrap exposes only a safe typed identity or context classification.
func (e MigrationError) Unwrap() error { return e.cause }

// ReferenceMigrationApply executes only an exact independently rebuilt plan.
// It holds one native global lock/connection from discovery through every
// namespace and checkpoint. Before any write it validates all current histories,
// selected guards, original sources and the full plan, not merely its digest.
// Only native transactional receipts explain a same-command prefix; externally
// matching schema/history is never adopted. Each batch commits native SQL,
// ledger and attribution together. Audit fresh preflight/history is one batch.
//
// Apply is disabled without an explicit operator policy. It never starts during
// construction/Check/Plan. Calls join Close's cancellation/drain lifetime and
// share no in-memory execution authority. Retry the exact original request to
// reconcile unknown outcomes; no new command/key/plan can claim that progress.
// The borrowed pool remains open. Cleanup uses its finite independent budget.
func (s StoreSet) ReferenceMigrationApply(ctx context.Context, input ReferenceMigrationApplyRequest) (out ReferenceMigrationApplyResult, failure error) {
	req, ids, err := copyMigrationApplyRequest(input)
	if err != nil {
		return out, err
	}
	bounded, _, finish, err := s.beginMigrationOperation(ctx, ids)
	if err != nil {
		return out, err
	}
	defer finish()
	policy := s.state.migrations
	if policy == nil {
		return out, identity.UnavailableError{}
	}
	out.Result = MigrationApplyResult{command: req.CommandID, digest: req.Plan.Digest, state: MigrationApplyPending}
	fail := func(state MigrationApplyState, err error) (ReferenceMigrationApplyResult, error) {
		out.Result.state = state
		return out, MigrationError{state: state, cause: err}
	}
	keyDigest, err := req.IdempotencyKey.Digest(policy.LookupKey)
	if err != nil {
		return ReferenceMigrationApplyResult{}, identity.InvalidInputError{Field: "idempotency_key"}
	}
	idempotency, fingerprint := migrationApplyBindings(*policy, req.Plan.Digest, keyDigest)
	catalog, err := s.migrationCatalog(bounded)
	if err != nil {
		return fail(MigrationApplyPending, checkFailure(bounded, err))
	}
	discovery := migrationDiscoveryIDs(catalog, ids)
	histories, err := selectMigrationHistories(catalog, discovery)
	if err != nil {
		return ReferenceMigrationApplyResult{}, err
	}
	db := stdlib.OpenDBFromPool(s.state.pool.Raw())
	defer db.Close()
	db.SetMaxOpenConns(1)
	backend, err := migrationdb.New(db, migrationdb.WithLockTimeout(policy.LockTimeout), migrationdb.WithOperationTimeout(s.state.config.PrimaryTimeout), migrationdb.WithStatementTimeout(s.state.config.PrimaryTimeout))
	if err != nil {
		return fail(MigrationApplyPending, identity.UnavailableError{})
	}
	owned, err := backend.AcquireCommand(bounded)
	if err != nil {
		if bounded.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return fail(MigrationApplyLocked, identity.UnavailableError{})
		}
		return fail(MigrationApplyPending, checkFailure(bounded, err))
	}
	executed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), policy.CleanupTimeout)
		defer cancel()
		if err := owned.Release(cleanup); err != nil {
			state, cause := MigrationApplyPending, error(identity.UnavailableError{})
			if executed {
				state, cause = MigrationApplyUnknown, identity.UnknownCommitError{CommandID: req.CommandID}
			}
			out.Result.state = state
			failure = MigrationError{state: state, cause: cause}
		}
	}()
	progress, exists, err := owned.ReadProgress(bounded, string(req.CommandID))
	if err != nil {
		return failMigrationNative(out, bounded, req.CommandID, err)
	}
	if exists && (progress.Fingerprint() != fingerprint || progress.IdempotencyDigest() != idempotency) {
		return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
	}
	snapshots, err := discoverOwnedMigrations(bounded, owned, histories, s.state)
	if err != nil {
		return failMigrationNative(out, bounded, req.CommandID, err)
	}
	for _, snapshot := range snapshots {
		for _, status := range snapshot.statuses {
			if status.Compatibility == MigrationDirty {
				return fail(MigrationApplyDirty, identity.ConflictError{CommandID: req.CommandID})
			}
			if status.Compatibility == MigrationIncompatible {
				return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
			}
		}
	}
	// Native original base is the only allowed planning base on reconstruction.
	// Execute independently checks current == base + exact attributed prefix.
	if exists {
		base := progress.Base()
		if len(base) != len(snapshots) {
			return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
		}
		for i := range snapshots {
			if base[i].Namespace != snapshots[i].history.namespace {
				return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
			}
			snapshots[i].records = base[i].Records
			snapshots[i].statuses = snapshots[i].history.project(base[i].Records)
		}
	}
	rebuilt, err := buildMigrationPlan(snapshots, ids)
	if err != nil || !equalMigrationPlan(rebuilt, req.Plan) {
		return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
	}
	native, err := migrationCommand(req, snapshots, fingerprint, idempotency)
	if err != nil {
		return fail(MigrationApplyIncompatible, identity.ConflictError{CommandID: req.CommandID})
	}
	executed = true
	progress, err = owned.Execute(bounded, native)
	if progress.ID() != "" {
		out.Result.receipts = contributorReceipts(progress, histories, ids)
	}
	if err != nil {
		return failMigrationNative(out, bounded, req.CommandID, err)
	}
	if !progress.Complete() {
		return fail(MigrationApplyUnknown, identity.UnknownCommitError{CommandID: req.CommandID})
	}
	out.Result.state = MigrationApplied
	return out, nil
}

func copyMigrationApplyRequest(input ReferenceMigrationApplyRequest) (ReferenceMigrationApplyRequest, []ModuleID, error) {
	bad := func() (ReferenceMigrationApplyRequest, []ModuleID, error) {
		return ReferenceMigrationApplyRequest{}, nil, identity.InvalidInputError{Field: "reference_migration_apply"}
	}
	id := string(input.CommandID)
	if len(id) < 16 || len(id) > 128 {
		return bad()
	}
	for i := range len(id) {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return bad()
		}
	}
	p := input.Plan
	if len(p.Modules) < 1 || len(p.Modules) > 128 || len(p.Steps) > 4096 || p.Digest == [32]byte{} || p.CatalogDigest == [32]byte{} || p.BaseLedgerDigest == [32]byte{} {
		return bad()
	}
	ids := make([]ModuleID, 0, len(p.Modules))
	for i, module := range p.Modules {
		if !migrationScope(module.Module) || i > 0 && p.Modules[i-1].Module >= module.Module {
			return bad()
		}
		ids = append(ids, ModuleID(module.Module))
	}
	for _, step := range p.Steps {
		if !slices.Contains(ids, step.Owner) || len(step.ID) < 1 || len(step.ID) > 128 || step.ToVersion <= step.FromVersion || step.SourceDigest == [32]byte{} || step.StepDigest != migrationStepDigest(step) {
			return bad()
		}
	}
	if migrationPlanDigest(p) != p.Digest {
		return bad()
	}
	input.Plan.Modules, input.Plan.Steps = slices.Clone(p.Modules), slices.Clone(p.Steps)
	return input, ids, nil
}

func equalMigrationPlan(a, b MigrationPlan) bool {
	return a.Digest == b.Digest && a.CatalogDigest == b.CatalogDigest && a.BaseLedgerDigest == b.BaseLedgerDigest && slices.Equal(a.Modules, b.Modules) && slices.Equal(a.Steps, b.Steps)
}

func migrationApplyBindings(p MigrationApplyPolicy, plan, key [32]byte) ([32]byte, [32]byte) {
	d := newMigrationDigest("apply-key-scope")
	d.string(string(p.TenantID))
	d.string(string(p.ActorID))
	d.string("identity.reference.migration-apply")
	d.digest(key)
	h := hmac.New(sha256.New, p.LookupKey[:])
	scope := d.sum()
	_, _ = h.Write(scope[:])
	lookup := [32]byte(h.Sum(nil))
	f := newMigrationDigest("apply-fingerprint")
	f.digest(plan)
	f.digest(lookup)
	f.number(uint64(p.LockTimeout))
	f.number(uint64(p.CleanupTimeout))
	return lookup, f.sum()
}

func selectMigrationHistories(catalog []migrationHistory, ids []ModuleID) ([]migrationHistory, error) {
	known := make(map[ModuleID]bool)
	var result []migrationHistory
	for _, h := range catalog {
		selected := false
		for _, owner := range h.owners {
			known[owner] = true
			selected = selected || slices.Contains(ids, owner)
		}
		if selected {
			result = append(result, h)
		}
	}
	for _, id := range ids {
		if !known[id] {
			return nil, identity.InvalidInputError{Field: "reference_modules"}
		}
	}
	return result, nil
}

func discoverOwnedMigrations(ctx context.Context, owned *migrationdb.CommandSession, histories []migrationHistory, state *storeState) ([]migrationSnapshot, error) {
	snapshots := make([]migrationSnapshot, 0, len(histories))
	for _, h := range histories {
		records, err := owned.ReadLedger(ctx, h.namespace)
		if err != nil {
			return nil, err
		}
		statuses := h.project(records)
		for _, g := range h.guards {
			if _, ok := h.owners[g.version]; !ok {
				continue
			}
			applied := slices.ContainsFunc(records, func(r migrations.Record) bool { return r.Version() == g.version })
			if applied {
				continue
			}
			// The native catalog API has no constraint identity kind. Read only
			// these exact extension identities from the same primary while the
			// command session retains global migration ownership. No second lock,
			// transaction, migration runner or adoption path is introduced.
			if len(g.constraints) != 0 {
				exists, err := g.exists(ctx, state)
				if err != nil {
					return nil, err
				}
				if exists {
					for owner, status := range statuses {
						if status.Compatibility != MigrationDirty {
							status.Compatibility = MigrationIncompatible
						}
						statuses[owner] = status
					}
				}
			}
			objects := guardCatalogIdentities(g)
			if len(objects) == 0 {
				continue
			}
			presence, err := owned.CatalogPresence(ctx, objects)
			if err != nil {
				return nil, err
			}
			if slices.Contains(presence, true) {
				for owner, status := range statuses {
					if status.Compatibility != MigrationDirty {
						status.Compatibility = MigrationIncompatible
					}
					statuses[owner] = status
				}
			}
		}
		snapshots = append(snapshots, migrationSnapshot{history: h, records: records, statuses: statuses})
	}
	return snapshots, nil
}

func guardCatalogIdentities(g migrationGuard) []migrationdb.CatalogIdentity {
	var result []migrationdb.CatalogIdentity
	if len(g.tables) == 0 && len(g.columns) == 0 && len(g.functions) == 0 && len(g.constraints) == 0 {
		result = append(result, migrationdb.CatalogIdentity{Kind: migrationdb.CatalogSchema, Schema: g.schema})
	}
	for _, name := range g.tables {
		result = append(result, migrationdb.CatalogIdentity{Kind: migrationdb.CatalogRelation, Schema: g.schema, Name: name})
	}
	for _, name := range g.roles {
		result = append(result, migrationdb.CatalogIdentity{Kind: migrationdb.CatalogRole, Name: name})
	}
	for _, name := range g.columns {
		table, column, _ := strings.Cut(name, ".")
		result = append(result, migrationdb.CatalogIdentity{Kind: migrationdb.CatalogColumn, Schema: g.schema, Name: table, Member: column})
	}
	for _, name := range g.functions {
		result = append(result, migrationdb.CatalogIdentity{Kind: migrationdb.CatalogFunction, Schema: g.schema, Name: name})
	}
	return result
}

func migrationCommand(req ReferenceMigrationApplyRequest, snapshots []migrationSnapshot, fingerprint, idempotency [32]byte) (migrationdb.CommandRequest, error) {
	result := migrationdb.CommandRequest{ID: string(req.CommandID), Fingerprint: fingerprint, IdempotencyDigest: idempotency}
	position := 0
	for _, snapshot := range snapshots {
		h := snapshot.history
		result.Histories = append(result.Histories, migrationdb.CommandHistory{Namespace: h.namespace, Source: h.history, Base: snapshot.records})
		var selected []migrations.Migration
		for position < len(req.Plan.Steps) {
			step := req.Plan.Steps[position]
			if step.SourceDigest != migrationSourceDigest(h) || h.owners[migrations.Version(step.ToVersion)] != step.Owner {
				break
			}
			found := false
			for _, m := range h.history {
				if uint64(m.Version()) == step.ToVersion {
					selected = append(selected, m)
					found = true
					break
				}
			}
			if !found {
				return migrationdb.CommandRequest{}, identity.ConflictError{}
			}
			position++
		}
		if len(selected) == 0 {
			continue
		}
		if len(snapshot.records) == 0 && h.preflight != "" {
			if len(selected) != len(h.history) {
				return migrationdb.CommandRequest{}, identity.ConflictError{}
			}
			result.Batches = append(result.Batches, migrationdb.CommandBatch{Namespace: h.namespace, Migrations: selected, Preflight: h.preflight})
		} else {
			for _, step := range selected {
				result.Batches = append(result.Batches, migrationdb.CommandBatch{Namespace: h.namespace, Migrations: []migrations.Migration{step}})
			}
		}
	}
	if position != len(req.Plan.Steps) {
		return migrationdb.CommandRequest{}, identity.ConflictError{}
	}
	return result, nil
}

func contributorReceipts(p migrationdb.CommandProgress, histories []migrationHistory, ids []ModuleID) []MigrationContributorReceipt {
	versions := make(map[ModuleID]uint64)
	for _, r := range p.Receipts() {
		for _, h := range histories {
			if h.namespace == r.Namespace {
				owner := h.owners[r.Record.Version()]
				versions[owner] = max(versions[owner], uint64(r.Record.Version()))
			}
		}
	}
	var result []MigrationContributorReceipt
	for _, id := range ids {
		if version, ok := versions[id]; ok {
			result = append(result, MigrationContributorReceipt{Module: id, Version: version})
		}
	}
	return result
}

func failMigrationNative(out ReferenceMigrationApplyResult, ctx context.Context, id identity.CommandID, err error) (ReferenceMigrationApplyResult, error) {
	state, cause := MigrationApplyPending, error(identity.UnavailableError{})
	switch {
	case errors.Is(err, migrationdb.ErrCommandOutcomeUnknown):
		state, cause = MigrationApplyUnknown, identity.UnknownCommitError{CommandID: id}
	case errors.Is(err, migrations.ErrDirty):
		state, cause = MigrationApplyDirty, identity.ConflictError{CommandID: id}
	case errors.Is(err, migrationdb.ErrCommandConflict), errors.Is(err, migrationdb.ErrLedgerConflict),
		errors.Is(err, migrations.ErrInvalidRecord), errors.Is(err, migrations.ErrChecksumMismatch),
		errors.Is(err, migrations.ErrRenamedMigration), errors.Is(err, migrations.ErrDeletedMigration),
		errors.Is(err, migrations.ErrReorderedHistory), errors.Is(err, migrations.ErrHistoryLimit),
		errors.Is(err, migrationdb.ErrResourceLimit):
		state, cause = MigrationApplyIncompatible, identity.ConflictError{CommandID: id}
	case ctx.Err() != nil:
		cause = ctx.Err()
	}
	out.Result.state = state
	return out, MigrationError{state: state, cause: cause}
}
