package postgres

import (
	"bytes"
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Work is a generation-bound transaction capability for trusted enlisted
// adapters, never an application SQL gateway. Only the coordinator may create
// it; no public constructor or transaction/connection/closure API exists.
// Copies share lifetime and failure state. Methods and returned rows must be
// used serially and must not be retained beyond the contributor invocation.
// Any SQL, scan, budget or cancellation failure poisons subsequent execution.
// Zero is invalid. Coordinator.Begin issues Work for creation and field-update
// mutation; other domain profiles remain under development. Work alone is not
// complete command authority.
type Work struct{ state *workState }

type workState struct {
	tx                  pgx.Tx
	ctx                 context.Context
	cancel              context.CancelFunc
	binding             identity.CommandBinding
	generation          uint64
	closed              bool
	failed              error
	rows                *WorkRows
	audits              *workAudits
	lifecycle           *workLifecycle
	registry            *contributorRegistryState
	sqlStarted          bool
	execution           *domainExecution
	creation            *identity.User
	profile             *identity.UserProfile
	update              *identity.User
	status              *identity.CommandResult
	identifier          *identifierWorkResult
	identifierAdmission *identifierAdmissionProgress
	feature             *FeatureRegistration
	subjectType         string
	featureAttempted    bool
	featureReceipt      *identity.FeatureReceipt
	featureInvocation   FeatureExecutionContributor
	delivery            *workDelivery
	issuance            *workIssuance
	credentialIntent    *CredentialCompromiseIntent
	credentialReceipt   *CredentialCompromiseReceipt
	counterCommand      *identity.Command
	riskCommand         *identity.Command
}

// newWork is private: only the sole coordinator may call it after verifying
// the complete plan/participants and beginJournal in this exact transaction.
func newWork(ctx context.Context, tx pgx.Tx, binding identity.CommandBinding, q claimRequest, fence journalWorkFence) (Work, error) {
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	if q.feature != nil {
		probe.Feature = &identity.FeatureReceipt{Operation: *q.feature}
	}
	if ctx == nil || tx == nil || fence.generation == 0 || fence.readStarted.IsZero() || !postgresExactTime(fence.now) || !postgresExactTime(fence.until) || !fence.until.After(fence.now) || fence.until.Sub(fence.now) > time.Minute || probe.Validate() != nil || binding.CommandID != q.commandID || binding.TenantID != q.tenant || binding.OperationID != q.purpose || !bytes.Equal(commandSafeFields(binding, q.feature), q.safeFields) {
		return Work{}, invalidWork()
	}
	if _, ok := ctx.Deadline(); !ok {
		return Work{}, invalidWork()
	}
	// Never restart freshness on construction or cache a new full lease. Local
	// monotonic lifetime begins before the authoritative clock read's roundtrip.
	bounded, cancel := context.WithDeadline(ctx, fence.readStarted.Add(fence.until.Sub(fence.now)))
	if bounded.Err() != nil {
		cancel()
		return Work{}, readFailure(bounded, bounded.Err())
	}
	return Work{state: &workState{tx: tx, ctx: bounded, cancel: cancel, binding: binding, generation: fence.generation}}, nil
}

// Scope returns the exact immutable core command binding, not current policy
// or an authentication proof. Closed, failed or expired Work returns no scope.
func (w Work) Scope() (identity.CommandBinding, error) {
	if err := w.usable(); err != nil {
		return identity.CommandBinding{}, err
	}
	return w.state.binding, nil
}

// Exec runs one trusted compile-time SELECT/INSERT/UPDATE/DELETE/WITH statement
// using the extended protocol, including with zero parameters. It returns the
// affected-row count after all results are bounded and drained. SQL is at most
// 64 KiB; parameters use the closed scalar profile documented on Query. This
// denies transaction-control commands and driver options, not malicious SQL
// inside trusted adapters. Contributors must enforce owner/tenant scope and
// cannot invoke SQL functions that alter ownership, isolation or external state.
func (w Work) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	rows, err := w.Query(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := w.usable(); err != nil {
		return 0, err
	}
	return rows.native.CommandTag().RowsAffected(), nil
}

// Query executes one trusted compile-time statement and returns owned bounded
// rows with no raw driver/connection access. Exactly one result may be active;
// close it before another query. Callers must not concurrently mutate args.
// At most 64 parameters and 1 MiB aggregate scalar bytes are accepted: nil,
// bool, int/int16/int32/int64, uint32/uint64, finite float64, string, []byte and
// microsecond-exact time.Time in PostgreSQL UTC years 1..9999. Driver execution
// modes, query rewriters and custom marshalers are rejected without invocation.
// At most 256 rows, 64 columns and 1 MiB aggregate raw result bytes are returned;
// budget overflow poisons Work and requires coordinator abort. These limits
// bound delivered results, not a PostgreSQL statement's server-side work.
// The earlier caller or Work deadline wins; Work cancellation cancels reads.
func (w Work) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	if ctx == nil || w.state.rows != nil {
		return nil, invalidWork()
	}
	parameters, err := workParameters(sql, args)
	if err != nil {
		return nil, w.fail(ctx, err)
	}
	if ctx.Err() != nil {
		return nil, w.fail(ctx, ctx.Err())
	}
	deadline, _ := w.state.ctx.Deadline()
	call, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(w.state.ctx, cancel)
	// A fresh fixed codec map excludes caller-installed codecs. Query/Exec can
	// resolve SQL as an explicit prepared-statement name before choosing a mode,
	// so issue the exact bounded text through extended ExecParams directly.
	codecs := pgtype.NewMap()
	values, oids, formats, err := encodeWorkParameters(codecs, parameters)
	if err != nil {
		failure := w.fail(call, err)
		stop()
		cancel()
		return nil, failure
	}
	connection := w.state.tx.Conn().PgConn()
	if connection.TxStatus() != 'T' {
		failure := w.fail(call, identity.UnavailableError{})
		stop()
		cancel()
		return nil, failure
	}
	w.state.sqlStarted = true
	native := pgx.RowsFromResultReader(codecs, connection.ExecParams(call, sql, values, oids, formats, nil))
	// Resolve initial execution errors before returning a cursor, preserving
	// their classification before cancellation used solely for cleanup.
	first := native.Next()
	if !first && native.Err() != nil {
		failure := w.fail(call, native.Err())
		stop()
		cancel()
		return nil, failure
	}
	rows := &WorkRows{work: w, native: native, ctx: call, cancel: cancel, stop: stop, prefetched: first}
	w.state.rows = rows
	if !first {
		rows.Close()
	}
	return rows, nil
}

// DatabaseTime reads a fresh primary UTC clock instant inside this transaction.
// It does not renew the original Work lifetime or reservation lease.
func (w Work) DatabaseTime(ctx context.Context) (time.Time, error) {
	rows, err := w.Query(ctx, "SELECT clock_timestamp()")
	if err != nil {
		return time.Time{}, err
	}
	defer rows.Close()
	var now time.Time
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return time.Time{}, err
		}
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	if err := rows.Scan(&now); err != nil {
		return time.Time{}, err
	}
	if rows.Next() {
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, err
	}
	if !postgresExactTime(now) {
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return now.UTC(), nil
}

func (w Work) usable() error {
	if w.state == nil || w.state.closed {
		return invalidWork()
	}
	if w.state.failed != nil {
		return w.state.failed
	}
	if w.state.ctx.Err() != nil {
		return w.fail(w.state.ctx, w.state.ctx.Err())
	}
	return nil
}

func (w Work) fail(ctx context.Context, err error) error {
	if w.state.failed == nil {
		if w.state.ctx.Err() != nil {
			ctx = w.state.ctx
		}
		if _, ok := err.(identity.InvalidInputError); ok {
			w.state.failed = err
		} else if _, ok := err.(identity.ConflictError); ok && ctx.Err() == nil {
			// Preserve an owned domain conflict without retaining driver causes.
			w.state.failed = identity.ConflictError{}
		} else if _, ok := err.(identity.ForbiddenError); ok && ctx.Err() == nil {
			w.state.failed = identity.ForbiddenError{}
		} else {
			w.state.failed = readFailure(ctx, err)
		}
	}
	return w.state.failed
}

// The coordinator invalidates all aliases and cancels/closes active rows before
// closing its transaction. It remains the sole commit/rollback owner.
func invalidateWork(w Work) {
	if w.state == nil || w.state.closed {
		return
	}
	w.state.closed = true
	if w.state.issuance != nil {
		clear(w.state.issuance.grants)
		w.state.issuance.invocation = nil
	}
	if w.state.delivery != nil {
		clear(w.state.delivery.envelopes)
		w.state.delivery.invocation = nil
		w.state.delivery.bytes = 0
	}
	w.state.counterCommand = nil
	w.state.riskCommand = nil
	w.state.cancel()
	if w.state.rows != nil {
		w.state.rows.Close()
	}
}

func invalidWork() error { return identity.InvalidInputError{Field: "work"} }

// WorkRows is a Work-owned serial result cursor with no driver escape hatch.
// Scan permits only pointers to the closed scalar types accepted by Query,
// plus **string/**int64/**time.Time for nullable columns and nil to skip a
// column. Custom scanners are rejected without invocation. Next must precede
// Scan. Close is idempotent; Err must be inspected after Next returns false.
// Rows become permanently unusable when their Work is invalidated; zero is
// invalid and safely rejects reads. On a Scan error, discard every destination:
// the driver may have populated an earlier column before rejecting a later one.
type WorkRows struct {
	work                      Work
	native                    pgx.Rows
	ctx                       context.Context
	cancel                    context.CancelFunc
	stop                      func() bool
	closed, ready, prefetched bool
	count, bytes              int
	err                       error
}

// Next advances within the row/byte budgets; false means completion or failure.
func (r *WorkRows) Next() bool {
	if r == nil || r.closed {
		return false
	}
	if err := r.usable(); err != nil {
		r.err = err
		r.Close()
		return false
	}
	if r.prefetched {
		r.prefetched = false
	} else if !r.native.Next() {
		r.Close()
		return false
	}
	if err := r.usable(); err != nil {
		r.err = err
		r.Close()
		return false
	}
	r.count++
	values := r.native.RawValues()
	if r.count > 256 || len(values) > 64 {
		r.err = r.work.fail(r.ctx, identity.UnavailableError{})
		r.Close()
		return false
	}
	for _, v := range values {
		if len(v) > 1<<20-r.bytes {
			r.err = r.work.fail(r.ctx, identity.UnavailableError{})
			r.Close()
			return false
		}
		r.bytes += len(v)
	}
	r.ready = true
	return true
}

// Scan decodes only closed typed destinations; it never invokes RowScanner.
func (r *WorkRows) Scan(dest ...any) error {
	if r == nil || r.closed || !r.ready {
		return invalidWork()
	}
	if err := r.usable(); err != nil {
		r.err = err
		r.Close()
		return err
	}
	if !workDestinations(dest) {
		r.err = r.work.fail(r.ctx, invalidWork())
		r.Close()
		return r.err
	}
	if err := r.native.Scan(dest...); err != nil {
		r.err = r.work.fail(r.ctx, err)
		r.Close()
		return r.err
	}
	if err := r.usable(); err != nil {
		r.err = err
		r.Close()
		return err
	}
	return nil
}

func (r *WorkRows) usable() error {
	if err := r.work.usable(); err != nil {
		return err
	}
	// The driver can already hold prefetched data, so network cancellation
	// alone cannot fence delivery against the Query caller's shorter lifetime.
	if err := r.ctx.Err(); err != nil {
		return r.work.fail(r.ctx, err)
	}
	return nil
}

// Close releases this cursor without committing or rolling back the Work.
func (r *WorkRows) Close() {
	if r == nil || r.closed {
		return
	}
	r.closed = true
	r.ready = false
	if r.native == nil {
		r.err = invalidWork()
		return
	}
	// Failure must stop the server stream, not drain an arbitrarily large
	// remaining result after a row/byte budget has already been exceeded.
	if r.err != nil {
		r.cancel()
	}
	r.native.Close()
	if err := r.native.Err(); err != nil && r.err == nil {
		r.err = r.work.fail(r.ctx, err)
	}
	r.stop()
	r.cancel()
	if r.work.state.rows == r {
		r.work.state.rows = nil
	}
}

// Err returns only redacted identity errors, never PostgreSQL diagnostics.
func (r *WorkRows) Err() error {
	if r == nil {
		return invalidWork()
	}
	if r.err != nil {
		return r.err
	}
	if r.work.state == nil || r.work.state.closed {
		return invalidWork()
	}
	return nil
}
