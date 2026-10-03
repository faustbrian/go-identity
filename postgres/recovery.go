package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// RecoverCommand authorizes current disclosure using QueryPolicy before
// attempting primary reconciliation. It exposes metadata only, never private
// replay fields. Missing/wrong-scope/denied requests retain QueryCommand's
// decision/read shape and perform no mutation. Live pending is observational.
// Expired creation, field-update and identifier-attachment recovery resolves
// only the exact frozen registry entries
// through RecoveryContributor, takes a new generation, and aborts only after
// all participants prove non-commit and a required failure audit is persisted
// in the same guarded transaction. Missing/unknown/conflicting evidence leaves
// pending; no success is reconstructed. Commit-attempt failure is Unknown.
// Identifier attachment additionally requires the typed capability release
// phase: only unanimous non-commit proof permits terminal release in the same
// transaction. It performs no command replay or network callbacks. Other
// one-time profiles and recovery-deadline/operator alerting remain unfinished.
func (c *Coordinator) RecoverCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (CommandRecord, error) {
	if c == nil || ctx == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return CommandRecord{}, coordinatorError()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	r, err := c.queryCommandReceipt(bounded, q, caller)
	if err == nil && r.Outcome == identity.CommitOutcomeInProgress {
		r, err = c.recoverCommandReceipt(bounded, q)
	}
	if r.Outcome == identity.CommitOutcomeUnknown {
		return CommandRecord{}, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	return commandRecord(r), err
}

// Trusted storage seam behind the core service's current authorization and
// redaction; unlike public RecoverCommand it must not manufacture a caller.
func (c *Coordinator) recoverCommandReceipt(ctx context.Context, q identity.RecoveryQuery) (result identity.CommandResult, err error) {
	if c == nil || ctx == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.maximumDuration <= 0 {
		return result, coordinatorError()
	}
	if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil {
		return result, identity.InvalidInputError{Field: "command_id"}
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	tx, e := c.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return result, readFailure(bounded, e)
	}
	closed := false
	var work Work
	defer func() {
		panicked := recover() != nil
		invalidateWork(work)
		if !closed {
			cleanup, stop := context.WithTimeout(context.Background(), c.maximumDuration)
			defer stop()
			if tx.Rollback(cleanup) != nil && result.Binding.CommandID != "" {
				result = identity.CommandResult{Binding: result.Binding, Outcome: identity.CommitOutcomeUnknown}
				err = identity.UnavailableError{}
			}
		}
		if panicked {
			err = identity.UnavailableError{}
		}
	}()
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var locked []byte
	// Historical lookup never inserts a claim or requires original secret input.
	e = tx.QueryRow(bounded, `SELECT command_id FROM identity.identity_command_id_claims WHERE command_id=$1 FOR UPDATE`, id).Scan(&locked)
	if errors.Is(e, pgx.ErrNoRows) {
		return result, identity.ForbiddenError{}
	}
	if e != nil {
		return result, readFailure(bounded, e)
	}
	observed, e := readRecoveryObservation(bounded, tx, id)
	result, err = commandReceipt(q, observed, e)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return result, err
	}
	// The claim lock precedes the scoped journal lock, also after a lock wait.
	e = tx.QueryRow(bounded, `SELECT command_id FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(q.TenantID), q.OperationID).Scan(&locked)
	if e != nil {
		return result, readFailure(bounded, e)
	}
	observed, e = readRecoveryObservation(bounded, tx, id)
	result, err = commandReceipt(q, observed, e)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return result, err
	}
	if observed.until.After(observed.now) {
		return result, nil
	}
	if q.OperationID != "identity.user.create" && q.OperationID != "identity.profile.update" && q.OperationID != "identity.user.update-admin" && q.OperationID != "identity.identifier.attach" {
		return result, identity.UnavailableError{}
	}
	fingerprint := [32]byte(observed.fingerprint)
	plan, e := decodeKernelPlan(result.Binding, fingerprint, observed.plan)
	if e != nil {
		return result, e
	}
	admitted, e := c.registry.admitKernelPlan(result.Binding, fingerprint, plan)
	if e != nil {
		return result, identity.UnavailableError{}
	}
	// An old persistence-only registration remains readable, but cannot supply
	// evidence. No takeover or prefix callback occurs without the full phase set.
	for _, entry := range admitted.contributors {
		if _, ok := entry.contributor.(RecoveryContributor); !ok {
			return result, identity.UnavailableError{}
		}
		if entry.descriptor.Owner == "capability/postgres" {
			if _, ok := entry.contributor.(CapabilityReleaseContributor); !ok {
				return result, identity.UnavailableError{}
			}
		}
	}
	if q.OperationID == "identity.identifier.attach" && (admitted.capability == nil || admitted.lifecycle == nil || admitted.lifecycle.BeforeVersion != 0) {
		return result, identity.UnavailableError{}
	}
	var owner [16]byte
	if _, e = rand.Read(owner[:]); e != nil || owner == ([16]byte{}) {
		return result, identity.UnavailableError{}
	}
	request := claimRequest{commandID: q.CommandID, tenant: q.TenantID, purpose: q.OperationID, safeFields: observed.scope}
	journal, e := reserveJournal(bounded, tx, request, claimReplay, owner, c.leaseDuration)
	if e != nil {
		return result, e
	}
	if journal.disposition != journalOwned {
		return result, identity.UnavailableError{}
	}
	var now, until time.Time
	readStarted := time.Now()
	if e = tx.QueryRow(bounded, `SELECT clock_timestamp(),lease_until FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, id, string(q.TenantID), q.OperationID).Scan(&now, &until); e != nil {
		return result, readFailure(bounded, e)
	}
	fence := journalWorkFence{generation: journal.generation, now: now, until: until, readStarted: readStarted}
	work, e = newWork(bounded, tx, result.Binding, request, fence)
	if e != nil {
		return result, e
	}
	work.state.registry = c.registry.state
	reservation := &reservationState{coordinator: c, request: request, plan: admitted, journal: journal, owner: owner}
	work.state.execution = &domainExecution{coordinator: c, reservation: reservation, ctx: bounded}
	if e = admitted.bindWork(work); e != nil {
		return result, e
	}
	if e = configureKernelWork(bounded, work); e != nil {
		return result, e
	}
	for _, entry := range admitted.contributors {
		if e = work.usable(); e != nil {
			return result, e
		}
		state := &recoveryWorkState{work: work, entry: entry, plan: admitted, active: true}
		status, failure := invokeRecovery(bounded, entry.contributor.(RecoveryContributor), RecoveryWork{state: state})
		state.active = false
		if failure != nil || work.state.rows != nil || work.usable() != nil {
			return result, identity.UnavailableError{}
		}
		if status != RecoveryNotCommitted {
			return result, identity.UnavailableError{}
		}
	}
	// All negative evidence was collected while old writers and tenant mutations
	// were excluded. Required failure evidence and the receipt close atomically.
	now, e = work.DatabaseTime(bounded)
	if e != nil {
		return result, e
	}
	record, e := kernelMutationAudit(bounded, result.Binding, admitted.lifecycle.BeforeVersion, now, "dependency-failure")
	if e != nil {
		return result, e
	}
	if e = work.StageAudit(admitted.audits[0].EventIndex, record); e != nil {
		return result, e
	}
	if e = c.persistAuditPhase(work); e != nil {
		return result, identity.UnavailableError{}
	}
	if e = c.releaseCapability(bounded, work, admitted, journal); e != nil {
		return result, identity.UnavailableError{}
	}
	// Contributor return values cannot erase a latched local/SQL failure.
	if e = work.usable(); e != nil {
		return result, e
	}
	aborted := identity.CommandResult{Binding: result.Binding, Outcome: identity.CommitOutcomeNotCommitted}
	if e = terminalizeJournal(work.state.ctx, tx, request, journal, owner, aborted, "dependency-failure"); e != nil {
		return result, e
	}
	deadline, _ := work.state.ctx.Deadline()
	commit, stop := context.WithDeadline(bounded, deadline)
	defer stop()
	invalidateWork(work)
	closed = true
	if e = tx.Commit(commit); e != nil {
		return identity.CommandResult{Binding: result.Binding, Outcome: identity.CommitOutcomeUnknown}, readFailure(commit, e)
	}
	return aborted, identity.UnavailableError{}
}

func readRecoveryObservation(ctx context.Context, tx pgx.Tx, id []byte) (commandObservation, error) {
	var o commandObservation
	err := tx.QueryRow(ctx, `SELECT coalesce(c.tenant_id::text,''),coalesce(c.purpose,''),c.safe_fields,c.retired,j.state,j.lease_until,clock_timestamp(),j.result_version,j.terminal_class,j.result,j.command_plan,c.fingerprint
FROM identity.identity_command_id_claims c LEFT JOIN identity.commands j ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose WHERE c.command_id=$1`, id).Scan(&o.tenant, &o.purpose, &o.scope, &o.retired, &o.state, &o.until, &o.now, &o.resultVersion, &o.class, &o.result, &o.plan, &o.fingerprint)
	return o, err
}

func invokeRecovery(ctx context.Context, p RecoveryContributor, w RecoveryWork) (status RecoveryStatus, err error) {
	defer func() {
		if recover() != nil {
			status, err = RecoveryUnknown, identity.UnavailableError{}
		}
	}()
	return p.RecoverParticipant(ctx, w)
}
