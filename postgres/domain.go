package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// domainExecution retains sole closure ownership. Work and all its aliases
// remain serial-use; a concurrent or repeated Begin consumes no second handle.
type domainExecution struct {
	coordinator *Coordinator
	reservation *reservationState
	ctx         context.Context
	cancel      context.CancelFunc
	// Only the owned creation bridge supplies prebuilt failure records. They
	// never unpoison Work or permit more domain SQL; Abort stages after rollback.
	abortAudits map[string]audit.Record
}

// Begin opens one bounded primary domain transaction after rechecking the
// exact claim, frozen plan, generation, owner and database-time lease. The
// opaque reservation is single-use, including failed admitted attempts;
// copies cannot create another Work. Foreign/zero reservations are rejected
// without consuming them. No authority is renewed after a lock wait.
// The caller MUST use Work serially and close it with Commit or Abort on every
// path, including panic (normally a deferred Abort). No background goroutine
// owns closure. A bounded PostgreSQL idle timeout additionally releases server
// locks for an abandoned idle handle, but does not release caller-held pool
// ownership: explicit closure remains required. Constructor pools remain
// caller-owned. Pre-observation failures are redacted; unproven rollback is
// identity.UnknownCommitError. This is still the creation-only profile.
func (c *Coordinator) Begin(ctx context.Context, r Reservation) (Work, error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || r.state == nil || r.state.coordinator != c || r.state.plan.belongsTo(c.registry) != nil {
		return Work{}, invalidWork()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	if err := bounded.Err(); err != nil {
		cancel()
		return Work{}, readFailure(bounded, err)
	}
	if !r.state.started.CompareAndSwap(false, true) {
		cancel()
		return Work{}, identity.ConflictError{}
	}
	tx, err := c.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		failure := readFailure(bounded, err)
		cancel()
		return Work{}, failure
	}
	fail := func(cause error) (Work, error) {
		_, result, failure := c.failedReservation(tx, r.state.plan.binding, identity.CommandResult{}, cause)
		cancel()
		if result.Outcome == identity.CommitOutcomeUnknown {
			return Work{}, identity.UnknownCommitError{CommandID: r.state.request.commandID}
		}
		return Work{}, failure
	}
	fence, err := beginJournal(bounded, tx, r.state.request, c.keys, r.state.journal, r.state.owner)
	if err != nil {
		return fail(err)
	}
	if _, err = c.freezePlan(bounded, tx, r.state.plan.binding, r.state.request, claimReplay, r.state.plan.snapshot()); err != nil {
		return fail(err)
	}
	w, err := newWork(bounded, tx, r.state.plan.binding, r.state.request, fence)
	if err != nil {
		return fail(err)
	}
	w.state.registry = c.registry.state
	if err := r.state.plan.bindWork(w); err != nil {
		invalidateWork(w)
		return fail(err)
	}
	w.state.execution = &domainExecution{coordinator: c, reservation: r.state, ctx: bounded, cancel: cancel}
	deadline, _ := w.state.ctx.Deadline()
	millis := time.Until(deadline).Milliseconds()
	if millis < 1 {
		millis = 1
	}
	if _, err := w.Exec(bounded, `SELECT set_config('idle_in_transaction_session_timeout',$1,true)`, strconv.FormatInt(millis, 10)+"ms"); err != nil {
		invalidateWork(w)
		return fail(err)
	}
	// All kernel writers use this tenant lock before aggregate mutations. Hash
	// collisions only add contention; they cannot merge scope or grant authority.
	key := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-tenant-lock-v1"), "tenant": cborText(string(w.state.binding.TenantID))}))
	if _, err := w.Exec(bounded, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(key[:8]))); err != nil {
		invalidateWork(w)
		return fail(err)
	}
	return w, nil
}

func (p *admittedKernelPlan) snapshot() CommandPlan {
	descriptors := make([]ContributorDescriptor, len(p.contributors))
	for i, entry := range p.contributors {
		descriptors[i] = entry.descriptor
	}
	result := CommandPlan{Contributors: descriptors, Audits: append([]AuditPlan(nil), p.audits...), Digest: p.digest}
	if p.lifecycle != nil {
		copy := *p.lifecycle
		result.Lifecycle = &copy
	}
	return result
}

// Descriptor identifies the owned kernel domain participant. Registration
// supplies identity only; ApplyUserCreation checks this exact instance is
// enlisted before using coordinator-owned Work. It performs no I/O.
func (*Repository) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
}

// ApplyUserCreation inserts an active version-1 structural user through this
// exact enlisted repository's Work. Returned User is provisional, not durable
// and not fresh authorization. Only Coordinator.Commit establishes its result.
// A repeated apply, changed command, foreign repository or unsupported nonempty
// attribute profile fails closed without silently dropping fields. Registered
// ordinary scalar/list attributes persist with the same mutation; unsupported
// secret/index profiles fail closed. Primary/unique-key
// conflicts are redacted and poison further SQL; the caller must Abort.
func (r *Repository) ApplyUserCreation(ctx context.Context, w Work, command identity.Command) (identity.User, error) {
	if r == nil || r.read == nil || ctx == nil {
		return identity.User{}, invalidWork()
	}
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	if w.state.execution == nil {
		return identity.User{}, invalidWork()
	}
	if w.state.creation != nil {
		return identity.User{}, w.fail(ctx, identity.ConflictError{})
	}
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == r {
			enlisted = true
		}
	}
	if !enlisted {
		return identity.User{}, w.fail(ctx, invalidWork())
	}
	spec, ok := command.CreateUser()
	if !ok || spec.Binding != w.state.binding {
		return identity.User{}, w.fail(ctx, identity.InvalidInputError{Field: "creation_command"})
	}
	q, err := prepareClaim(command, w.state.execution.coordinator.keys.retained[w.state.execution.coordinator.keys.current])
	if err != nil || !bytes.Equal(q.canonical, w.state.execution.reservation.request.canonical) {
		return identity.User{}, w.fail(ctx, identity.ConflictError{})
	}
	registered, attributes, err := r.prepareCreationAttributes(spec)
	if err != nil {
		return identity.User{}, w.fail(ctx, err)
	}
	if attributes != nil {
		if err := persistCreationSchema(ctx, w, registered); err != nil {
			return identity.User{}, err
		}
	}
	count, err := w.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1) ON CONFLICT(tenant_id,user_id) DO NOTHING`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return identity.User{}, err
	}
	if count != 1 {
		return identity.User{}, w.fail(ctx, identity.ConflictError{})
	}
	if attributes != nil {
		if _, err := w.Exec(ctx, `INSERT INTO identity.user_attributes(tenant_id,user_id,schema_id,schema_version,encoding_version,document) VALUES($1,$2,$3,$4,1,$5)`, string(spec.Binding.TenantID), string(spec.Binding.UserID), registered.schema.ID, registered.schema.Version, attributes); err != nil {
			return identity.User{}, err
		}
	}
	user := identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 1}
	w.state.creation = &user
	return user, nil
}

// Commit verifies the receipt against the owned actual creation and exact
// staged successful audit/lifecycle transition, persists registered audit then
// outbox phases through this same Work, and writes the terminal result before
// one primary commit. A caller-authored receipt cannot fabricate a mutation.
// All aliases and rows are invalidated before closure. Any error after commit
// begins returns Unknown with no rollback/retry. Pre-commit failures roll back
// through Abort; absent matching failure audit leaves pending/Unknown, not a
// fabricated terminal denial. No reveal-once output is produced. Zero/foreign/
// already-closed handles return an invalid-input error without closing others.
func (c *Coordinator) Commit(w Work, result identity.CommandResult) (identity.CommandResult, error) {
	if !c.owns(w) || w.state.closed {
		return identity.CommandResult{}, invalidWork()
	}
	defer func() {
		if !w.state.closed {
			_, _ = c.Abort(w, identity.UnavailableError{})
		}
	}()
	if err := w.usable(); err != nil {
		return c.Abort(w, err)
	}
	if w.state.rows != nil || w.state.creation == nil || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != w.state.binding || result.User != *w.state.creation {
		return c.Abort(w, identity.InvalidInputError{Field: "command_result"})
	}
	if err := completeAudits(w); err != nil {
		return c.Abort(w, err)
	}
	record := w.state.audits.records[0]
	attrs := record.Attributes()
	if record.ID() != result.AuditEventID || record.Outcome() != audit.OutcomeSucceeded || record.ReasonCode() != "completed" || !record.Changes().Redacted() || attrs["aggregate.before_version"] != "0" || attrs["aggregate.after_version"] != "1" {
		return c.Abort(w, invalidAudit())
	}
	if _, err := w.StagedLifecycle(); err != nil {
		return c.Abort(w, err)
	}
	if err := c.persistAuditPhase(w); err != nil {
		return c.Abort(w, identity.UnavailableError{})
	}
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "outbox/postgres" {
			if err := entry.contributor.(LifecycleContributor).PersistLifecycle(w.state.ctx, w); err != nil {
				return c.Abort(w, identity.UnavailableError{})
			}
		}
	}
	if err := w.usable(); err != nil {
		return c.Abort(w, err)
	}
	execution := w.state.execution
	r := execution.reservation
	if err := terminalizeJournal(w.state.ctx, w.state.tx, r.request, r.journal, r.owner, result, "committed"); err != nil {
		return c.Abort(w, err)
	}
	// Closing aliases cancels their context, not the commit. Preserve its
	// original lease deadline in a separately cancellable child of the caller.
	deadline, _ := w.state.ctx.Deadline()
	commit, cancelCommit := context.WithDeadline(execution.ctx, deadline)
	defer cancelCommit()
	invalidateWork(w)
	defer execution.cancel()
	if err := w.state.tx.Commit(commit); err != nil {
		return identity.CommandResult{Binding: w.state.binding, Outcome: identity.CommitOutcomeUnknown}, readFailure(commit, err)
	}
	return result, nil
}

// Abort proves domain rollback before attempting a separate guarded terminal
// transaction. A pre-staged exact failure/denial audit is required for a known
// NotCommitted receipt; missing or success evidence stays pending/Unknown for
// recovery. The terminal audit and receipt commit together. Lease loss, failed
// rollback or ambiguous terminalization is Unknown. Caller cancellation cannot
// prevent bounded detached cleanup. Errors are classified/redacted, never
// returned verbatim. Creation has no one-time participants to release; feature
// profiles and classified retry bookkeeping remain unsupported, not omitted.
func (c *Coordinator) Abort(w Work, cause error) (identity.CommandResult, error) {
	if !c.owns(w) || w.state.closed || cause == nil {
		return identity.CommandResult{}, invalidWork()
	}
	execution := w.state.execution
	r := execution.reservation
	class, reason, outcome, safeCause := abortClassification(cause)
	var record audit.Record
	complete := w.state.audits != nil && len(w.state.audits.records) == 1 && w.state.audits.staged[0]
	if candidate, exists := execution.abortAudits[class]; exists {
		record, complete = candidate, true
	} else if complete {
		record = w.state.audits.records[0]
	}
	if complete {
		attrs := record.Attributes()
		complete = record.Outcome() == outcome && record.ReasonCode() == reason && record.Changes().NoChange() && attrs["aggregate.before_version"] == "0" && attrs["aggregate.after_version"] == "0"
	}
	invalidateWork(w)
	cleanup, cancel := context.WithTimeout(context.Background(), c.maximumDuration)
	defer cancel()
	defer execution.cancel()
	unknown := identity.CommandResult{Binding: w.state.binding, Outcome: identity.CommitOutcomeUnknown}
	if err := w.state.tx.Rollback(cleanup); err != nil {
		return unknown, identity.UnavailableError{}
	}
	if !complete {
		return unknown, identity.UnavailableError{}
	}
	tx, err := c.pool.Raw().BeginTx(cleanup, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return unknown, readFailure(cleanup, err)
	}
	closed := false
	defer func() {
		if !closed {
			_, _, _ = c.failedReservation(tx, w.state.binding, unknown, identity.UnavailableError{})
		}
	}()
	fail := func(cause error) (identity.CommandResult, error) {
		closed = true
		_, result, err := c.failedReservation(tx, w.state.binding, unknown, cause)
		return result, err
	}
	fence, err := beginJournal(cleanup, tx, r.request, c.keys, r.journal, r.owner)
	if err != nil {
		return fail(err)
	}
	if _, err := c.freezePlan(cleanup, tx, w.state.binding, r.request, claimReplay, r.plan.snapshot()); err != nil {
		return fail(err)
	}
	terminal, err := newWork(cleanup, tx, w.state.binding, r.request, fence)
	if err != nil {
		return fail(err)
	}
	terminal.state.registry = c.registry.state
	terminal.state.execution = &domainExecution{coordinator: c, reservation: r, ctx: cleanup}
	defer invalidateWork(terminal)
	if err := r.plan.bindWork(terminal); err != nil {
		return fail(err)
	}
	if err := terminal.StageAudit(r.plan.audits[0].EventIndex, record); err != nil {
		return fail(err)
	}
	if err := c.persistAuditPhase(terminal); err != nil {
		return fail(identity.UnavailableError{})
	}
	result := identity.CommandResult{Binding: w.state.binding, Outcome: identity.CommitOutcomeNotCommitted}
	if err := terminalizeJournal(terminal.state.ctx, tx, r.request, r.journal, r.owner, result, class); err != nil {
		return fail(err)
	}
	deadline, _ := terminal.state.ctx.Deadline()
	commit, cancelCommit := context.WithDeadline(cleanup, deadline)
	defer cancelCommit()
	invalidateWork(terminal)
	closed = true
	if err := tx.Commit(commit); err != nil {
		return unknown, readFailure(commit, err)
	}
	return result, safeCause
}

func (c *Coordinator) owns(w Work) bool {
	return c != nil && c.registry != nil && w.state != nil && w.state.execution != nil && w.state.execution.coordinator == c && w.state.execution.reservation != nil && w.state.registry == c.registry.state
}

func (c *Coordinator) persistAuditPhase(w Work) error {
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "audit/postgres" {
			return entry.contributor.(AuditContributor).PersistAudits(w.state.ctx, w)
		}
	}
	return invalidAudit()
}

func abortClassification(cause error) (string, string, audit.Outcome, error) {
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	switch {
	case errors.As(cause, &forbidden):
		return "denied", "not_authorized", audit.OutcomeDenied, identity.ForbiddenError{}
	case errors.As(cause, &conflict):
		return "conflict", "conflict", audit.OutcomeDenied, identity.ConflictError{}
	case errors.Is(cause, context.Canceled):
		return "cancelled", "cancelled", audit.OutcomeFailed, identity.CancelledError{}
	case errors.Is(cause, context.DeadlineExceeded):
		return "deadline-exceeded", "timeout", audit.OutcomeFailed, identity.DeadlineExceededError{}
	default:
		return "dependency-failure", "provider_unavailable", audit.OutcomeFailed, identity.UnavailableError{}
	}
}
