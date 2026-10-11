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
	// Only the owned service bridge supplies prebuilt failure records. They
	// never unpoison Work or permit more domain SQL; Abort stages after rollback.
	abortAudits        map[string]audit.Record
	featureAbortAudits map[string][]audit.Record
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
// identity.UnknownCommitError. Creation and self-profile mutation are supported.
// One-use risk profiles additionally require the exact native current-check and
// finalize contributor; reservation/release-only owners remain unsupported.
// Protected feature counters additionally require the exact native current-check
// contributor. Begin grants no counter allowance: ApplyFeature and Commit each
// recheck under domain tenant exclusion, without recharging or renewing evidence.
func (c *Coordinator) Begin(ctx context.Context, r Reservation) (Work, error) {
	if r.state != nil && r.state.plan != nil && r.state.plan.otp != nil && otpExecutionOwner(r.state.plan) == nil {
		return Work{}, invalidWork()
	}
	// Reservation is not consumption authority. Require the complete current,
	// finalization and proof-bound release phase set before opening this profile.
	if r.state != nil && r.state.plan != nil && r.state.plan.captchaUse != nil && captchaExecutionParticipant(r.state.plan) == nil {
		return Work{}, invalidWork()
	}
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || r.state == nil || r.state.coordinator != c || r.state.plan.belongsTo(c.registry) != nil || r.state.plan.capability != nil && (r.state.plan.feature == nil || r.state.plan.feature.Operation != registrationEmailVerificationOperation() && r.state.plan.feature.Operation != credentialResetOperation() && r.state.plan.feature.Operation != magicLinkConsumeOperation()) || r.state.plan.risk != nil && riskExecutionParticipant(r.state.plan) == nil || r.state.plan.counters != nil && counterAdmissionParticipant(r.state.plan) == nil {
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
	if err := configureKernelWork(bounded, w); err != nil {
		invalidateWork(w)
		return fail(err)
	}
	return w, nil
}

func configureKernelWork(ctx context.Context, w Work) error {
	deadline, _ := w.state.ctx.Deadline()
	millis := time.Until(deadline).Milliseconds()
	if millis < 1 {
		millis = 1
	}
	if _, err := w.Exec(ctx, `SELECT set_config('idle_in_transaction_session_timeout',$1,true)`, strconv.FormatInt(millis, 10)+"ms"); err != nil {
		return err
	}
	// All kernel writers and recovery use this tenant lock before aggregate
	// access. Hash collisions add contention, never scope or authority.
	key := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-tenant-lock-v1"), "tenant": cborText(string(w.state.binding.TenantID))}))
	_, err := w.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(key[:8])))
	return err
}

func (p *admittedKernelPlan) snapshot() CommandPlan {
	descriptors := make([]ContributorDescriptor, len(p.contributors))
	for i, entry := range p.contributors {
		descriptors[i] = entry.descriptor
	}
	result := CommandPlan{Contributors: descriptors, Audits: append([]AuditPlan(nil), p.audits...), Digest: p.digest, CaptchaReplayReservation: p.captchaReplay, SignupAcceptance: p.signupAcceptance}
	result.MagicLinkRegistration = cloneMagicLinkRegistrationPlan(p.magicLinkRegistration)
	if p.identifierAdmission != nil {
		d := p.identifierAdmission.descriptor
		result.IdentifierAdmission = &d
	}
	result.Delivery = cloneDeliveryPlan(p.delivery)
	result.CapabilityIssuance = cloneCapabilityIssuancePlan(p.issuance)
	result.CaptchaEvidence = cloneCaptchaEvidencePlan(p.captchaUse)
	result.OTP = cloneOTPPlan(p.otp)
	if p.lifecycle != nil {
		copy := *p.lifecycle
		result.Lifecycle = &copy
	}
	if p.capability != nil {
		copy := *p.capability
		result.Capability = &copy
	}
	if p.risk != nil {
		copy := *p.risk
		result.RiskEvidence = &copy
	}
	if p.counters != nil {
		copy := *p.counters
		result.CommandCounters = &copy
	}
	if p.feature != nil {
		copy := *p.feature
		result.Feature, result.SubjectType = &copy, p.subjectType
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
	if w.state.creation != nil || w.state.profile != nil {
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
	user, err := r.insertCreation(ctx, w, spec)
	if err != nil {
		return identity.User{}, err
	}
	w.state.creation = &user
	return user, nil
}

// Shared kernel storage only; callers establish their own closed command and
// invocation ownership before using this primitive within the same Work.
func (r *Repository) insertCreation(ctx context.Context, w Work, spec identity.CreateUserCommand) (identity.User, error) {
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
	return user, nil
}

// Commit verifies the receipt against the owned actual mutation and exact
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
	if w.state.rows != nil || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != w.state.binding || !matchesDomainResult(w, result) {
		return c.Abort(w, identity.InvalidInputError{Field: "command_result"})
	}
	if err := completeAudits(w); err != nil {
		return c.Abort(w, err)
	}
	lifecycle := w.state.execution.reservation.plan.lifecycle
	for i, record := range w.state.audits.records {
		attrs := record.Attributes()
		if i == 0 && record.ID() != result.AuditEventID || record.Outcome() != audit.OutcomeSucceeded || record.ReasonCode() != "completed" || !record.Changes().Redacted() || attrs["aggregate.before_version"] != strconv.FormatUint(lifecycle.BeforeVersion, 10) || attrs["aggregate.after_version"] != strconv.FormatUint(lifecycle.AfterVersion, 10) {
			return c.Abort(w, invalidAudit())
		}
	}
	if _, err := w.StagedLifecycle(); err != nil {
		return c.Abort(w, err)
	}
	if err := c.persistCapabilityIssuance(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.persistDelivery(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.persistAuditPhase(w); err != nil {
		return c.Abort(w, identity.UnavailableError{})
	}
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "outbox/postgres" {
			var err error
			if w.state.execution.reservation.plan.magicLinkRegistration != nil {
				err = entry.contributor.(MagicLinkRegistrationLifecycleContributor).PersistMagicLinkRegistration(w.state.ctx, w)
			} else if w.state.credentialReceipt != nil {
				err = entry.contributor.(CredentialCompromiseLifecycleContributor).PersistCredentialCompromise(w.state.ctx, w)
			} else if w.state.resetIntent != nil {
				err = entry.contributor.(CredentialResetLifecycleContributor).PersistCredentialReset(w.state.ctx, w)
			} else if w.state.replacementReceipt != nil {
				err = entry.contributor.(CredentialReplacementLifecycleContributor).PersistCredentialReplacement(w.state.ctx, w)
			} else {
				err = entry.contributor.(LifecycleContributor).PersistLifecycle(w.state.ctx, w)
			}
			if err != nil {
				return c.Abort(w, identity.UnavailableError{})
			}
		}
	}
	if err := w.usable(); err != nil {
		return c.Abort(w, err)
	}
	execution := w.state.execution
	r := execution.reservation
	if r.plan.counters != nil {
		if w.state.counterCommand == nil {
			return c.Abort(w, invalidWork())
		}
		// Effects remain provisional. A slow native/audit/outbox phase cannot
		// substitute an earlier positive risk observation for current admission.
		if err := c.checkCommandCounters(w.state.ctx, w, *w.state.counterCommand); err != nil {
			return c.Abort(w, err)
		}
	}
	if r.plan.risk != nil {
		if w.state.riskCommand == nil {
			return c.Abort(w, invalidWork())
		}
		if err := c.runRiskExecution(w.state.ctx, w, *w.state.riskCommand, false); err != nil {
			return c.Abort(w, err)
		}
		if err := c.runRiskExecution(w.state.ctx, w, *w.state.riskCommand, true); err != nil {
			return c.Abort(w, err)
		}
	}
	if r.plan.captchaUse != nil {
		if w.state.captchaCommand == nil {
			return c.Abort(w, invalidWork())
		}
		if err := c.runCaptchaExecution(w.state.ctx, w, *w.state.captchaCommand, captchaCheck); err != nil {
			return c.Abort(w, err)
		}
		if err := c.runCaptchaExecution(w.state.ctx, w, *w.state.captchaCommand, captchaFinalize); err != nil {
			return c.Abort(w, err)
		}
	}
	if r.plan.otp != nil {
		if w.state.otpCommand == nil {
			return c.Abort(w, invalidWork())
		}
		if err := c.runOTPExecution(w.state.ctx, w, *w.state.otpCommand, otpCheck); err != nil {
			return c.Abort(w, err)
		}
		if err := c.runOTPExecution(w.state.ctx, w, *w.state.otpCommand, otpFinalize); err != nil {
			return c.Abort(w, err)
		}
	}
	if err := deliveryFresh(w); err != nil {
		return c.Abort(w, err)
	}
	if err := issuanceFresh(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.finalizeIdentifierCapability(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.finalizeEmailVerification(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.finalizeCredentialReset(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.finalizeMagicLinkConsumption(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.checkAuthenticatedCommand(w.state.ctx, w, true); err != nil {
		return c.Abort(w, err)
	}
	if err := terminalizeJournal(w.state.ctx, w.state.tx, r.request, r.journal, r.owner, result, "committed"); err != nil {
		return c.Abort(w, err)
	}
	if err := c.checkPreparedAdmission(w); err != nil {
		return c.Abort(w, err)
	}
	if err := c.checkFeatureCommit(w); err != nil {
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
		return featureOutcome(w.state.binding, r.request.feature, identity.CommitOutcomeUnknown, 0), readFailure(commit, err)
	}
	return result, nil
}

// Abort proves domain rollback before attempting a separate guarded terminal
// transaction. A pre-staged exact failure/denial audit is required for a known
// NotCommitted receipt; missing or success evidence stays pending/Unknown for
// recovery. The terminal audit and receipt commit together. Lease loss, failed
// rollback or ambiguous terminalization is Unknown. Caller cancellation cannot
// prevent bounded detached cleanup. Errors are classified/redacted, never
// returned verbatim. Native non-one-time features use coordinator-prebuilt
// classified failure records. Risk/CAPTCHA one-time owners release only after
// proven rollback; other one-time profiles and retry bookkeeping remain closed.
func (c *Coordinator) Abort(w Work, cause error) (identity.CommandResult, error) {
	if !c.owns(w) || w.state.closed || cause == nil {
		return identity.CommandResult{}, invalidWork()
	}
	execution := w.state.execution
	r := execution.reservation
	class, reason, outcome, safeCause := abortClassification(cause)
	var records []audit.Record
	// Previously validated immutable staging survives a poisoned/cancelled
	// domain handle; detached terminalization must revalidate it under its fence.
	complete := w.state.audits != nil && len(w.state.audits.records) > 0
	if complete {
		for _, staged := range w.state.audits.staged {
			complete = complete && staged
		}
	}
	if w.state.feature != nil {
		if candidates, exists := execution.featureAbortAudits[class]; exists {
			records, complete = candidates, true
		} else if complete {
			records = w.state.audits.records
		}
	} else if candidate, exists := execution.abortAudits[class]; exists {
		records, complete = []audit.Record{candidate}, true
	} else if complete {
		records = w.state.audits.records
	}
	complete = complete && len(records) == len(r.plan.audits)
	if complete {
		before := strconv.FormatUint(r.plan.lifecycle.BeforeVersion, 10)
		for _, record := range records {
			attrs := record.Attributes()
			complete = complete && record.Outcome() == outcome && record.ReasonCode() == reason && record.Changes().NoChange() && attrs["aggregate.before_version"] == before && attrs["aggregate.after_version"] == before
		}
	}
	invalidateWork(w)
	cleanup, cancel := context.WithTimeout(context.Background(), c.maximumDuration)
	defer cancel()
	defer execution.cancel()
	unknown := featureOutcome(w.state.binding, r.request.feature, identity.CommitOutcomeUnknown, 0)
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
	if r.plan.risk != nil || r.plan.capability != nil || r.plan.captchaUse != nil || r.plan.otp != nil {
		if err := configureKernelWork(cleanup, terminal); err != nil {
			return fail(err)
		}
	}
	for i, record := range records {
		if err := terminal.StageAudit(r.plan.audits[i].EventIndex, record); err != nil {
			return fail(err)
		}
	}
	if err := c.persistAuditPhase(terminal); err != nil {
		return fail(identity.UnavailableError{})
	}
	if err := c.releaseCapabilityAfterRollback(cleanup, terminal, r.plan, r.journal); err != nil {
		return fail(identity.UnavailableError{})
	}
	if err := c.releaseRiskAfterRollback(cleanup, terminal, r.plan, r.journal); err != nil {
		return fail(identity.UnavailableError{})
	}
	if err := c.releaseCaptcha(cleanup, terminal, r.plan, r.journal.generation, riskReleaseRollback); err != nil {
		return fail(identity.UnavailableError{})
	}
	if err := c.releaseOTP(cleanup, terminal, r.plan, r.journal.generation, riskReleaseRollback); err != nil {
		return fail(identity.UnavailableError{})
	}
	if terminal.state.rows != nil || terminal.usable() != nil {
		return fail(identity.UnavailableError{})
	}
	result := featureOutcome(w.state.binding, r.request.feature, identity.CommitOutcomeNotCommitted, 0)
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

func (c *Coordinator) persistAuditPhase(w Work) (err error) {
	defer func() {
		if recover() != nil {
			err = w.fail(w.state.ctx, identity.UnavailableError{})
		}
	}()
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
