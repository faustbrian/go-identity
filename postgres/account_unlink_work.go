package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// AccountUnlinkContributor is the trusted native policy and provider-cleanup
// participant for explicit self-unlink. It borrows the kernel's original Work;
// it may not create a transaction, call providers, retain handles or renew proof
// freshness. Preparation performs bounded primary reads only. Pure validation
// reconstructs the original proof, session, counters and policy declaration.
// Check repeats current admission; eligibility must come from actual credential
// and factor owners, never enabled reference rows alone. Persist consumes fresh
// proof and removes provider token custody provisionally. Finalize checks its
// exact effects. The kernel owns account rows, tombstones, epochs and closure.
// Instances must be comparable; concurrent commands use independent Work.
type AccountUnlinkContributor interface {
	RecoveryContributor
	PrepareAccountUnlink(context.Context, identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error)
	ValidateAccountUnlink(identity.Command, CommandPlan) error
	CheckAccountUnlink(context.Context, AccountUnlinkWork) error
	EligibleAccountUnlinkMethods(context.Context, AccountUnlinkWork, []identity.LoginMethod) ([]identity.LoginMethod, error)
	PersistAccountUnlink(context.Context, AccountUnlinkWork) error
	FinalizeAccountUnlink(context.Context, AccountUnlinkWork) error
}

type accountUnlinkPhase uint8

const (
	accountUnlinkCheck accountUnlinkPhase = iota + 1
	accountUnlinkEligibility
	accountUnlinkPersist
	accountUnlinkFinalCheck
	accountUnlinkFinalize
)

type accountUnlinkInvocation struct {
	work        Work
	participant AccountUnlinkContributor
	command     identity.AccountUnlinkCommand
	phase       accountUnlinkPhase
	active      bool
}

// AccountUnlinkWork borrows the original generation-bound transaction only for
// one native invocation. Copies share serial lifetime and failure state. Zero,
// foreign, poisoned and retained handles deny. Exec permits writes only during
// persistence/finalization; trusted read phases must not use mutating Query SQL.
// This is not a caller SQL sandbox. Close every
// cursor before returning. There is no transaction/connection/closure escape.
type AccountUnlinkWork struct{ state *accountUnlinkInvocation }

// Format omits proof, session, provider and transactional correlation.
func (AccountUnlinkWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountUnlinkWork(redacted)"))
}

// MarshalJSON rejects export of invocation custody.
func (AccountUnlinkWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit text export of invocation custody.
func (AccountUnlinkWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h AccountUnlinkWork) usable() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.usable()
}

func (h AccountUnlinkWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}

func (h AccountUnlinkWork) failure(ctx context.Context, err error) error {
	if err != nil {
		return h.state.work.fail(ctx, err)
	}
	return nil
}

// Command returns a value copy of the original signed intent only to the exact
// invoked participant. The boolean identifies final check/finalization; it does
// not indicate a commit, new admission or renewed freshness.
func (h AccountUnlinkWork) Command(p AccountUnlinkContributor) (identity.AccountUnlinkCommand, bool, error) {
	if err := h.usable(); err != nil {
		return identity.AccountUnlinkCommand{}, false, err
	}
	if !sameParticipant(p, h.state.participant) {
		return identity.AccountUnlinkCommand{}, false, h.deny()
	}
	command, err := identity.NewAccountUnlinkCommand(h.state.command)
	if err != nil {
		return identity.AccountUnlinkCommand{}, false, h.deny()
	}
	spec, _ := command.UnlinkAccount()
	return spec, h.state.phase == accountUnlinkFinalCheck || h.state.phase == accountUnlinkFinalize, nil
}

// PersistenceIntent lends the exact signed command only during the provisional
// persistence callback. Read/finalization callbacks cannot use it to consume
// the original password proof. Foreign or out-of-phase calls poison live Work.
func (h AccountUnlinkWork) PersistenceIntent(owner AccountUnlinkContributor) (identity.AccountUnlinkCommand, error) {
	spec, _, err := h.Command(owner)
	if err != nil {
		return identity.AccountUnlinkCommand{}, err
	}
	if h.state.phase != accountUnlinkPersist {
		return identity.AccountUnlinkCommand{}, h.deny()
	}
	return spec, nil
}

// CredentialAuthorityVersion returns the original epoch or, after application,
// only this Work's own successor. The owner must still authenticate the
// original credential and recheck the primary under this same transaction.
func (h AccountUnlinkWork) CredentialAuthorityVersion(owner AccountUnlinkContributor) (uint64, error) {
	spec, final, err := h.Command(owner)
	if err != nil {
		return 0, err
	}
	if !final {
		return spec.Change.ExpectedCredentialVersion, nil
	}
	progress := h.state.work.state.accountUnlink
	stage, _, _ := accountUnlinkPhaseStages(h.state.phase)
	if progress == nil || !progress.active || progress.stage != stage ||
		progress.receipt.AccountID != spec.Change.AccountID ||
		progress.receipt.ExpectedCredentialVersion != spec.Change.ExpectedCredentialVersion ||
		progress.receipt.CredentialVersion == 0 || progress.user.Version != spec.Change.ExpectedUserVersion+1 {
		return 0, h.deny()
	}
	return progress.receipt.CredentialVersion, nil
}

// Preparation lends the exact original password/session input and an owned
// copy of its retained encrypted issuer output to the currently invoked owner.
// Generation is original provenance, never a renewed lease or proof interval.
// It enables local authentication/restoration only, not generation, SQL,
// signing or consumption. Ordinary, foreign and returned invocations deny.
func (h AccountUnlinkWork) Preparation(p AccountUnlinkPreparationContributor) (identity.Command, []byte, uint64, error) {
	r, err := h.preparedReservation(p)
	if err != nil {
		return identity.Command{}, nil, 0, err
	}
	return *r.request.source, bytes.Clone(r.preparation.ciphertext), r.preparation.generation, nil
}

// OriginalFactorAuthorityVersion lends only the original declared generation
// to the exact native participant. It is not a current factor admission.
func (h AccountUnlinkWork) OriginalFactorAuthorityVersion(p AccountUnlinkPreparationContributor) (uint64, error) {
	r, err := h.preparedReservation(p)
	if err != nil {
		return 0, err
	}
	spec, _, ok := r.request.source.AccountUnlinkPreparationInput()
	if !ok || spec.FactorAuthorityVersion == 0 {
		return 0, h.deny()
	}
	return spec.FactorAuthorityVersion, nil
}

func (h AccountUnlinkWork) preparedReservation(p AccountUnlinkPreparationContributor) (*reservationState, error) {
	if _, _, err := h.Command(p); err != nil {
		return nil, err
	}
	e := h.state.work.state.execution
	if e == nil || e.coordinator == nil || e.reservation == nil || !e.coordinator.owns(h.state.work) || e.reservation.coordinator != e.coordinator {
		return nil, h.deny()
	}
	r := e.reservation
	if r.executionRequest == nil || r.preparation == nil {
		return nil, h.deny()
	}
	if _, err := accountUnlinkExecutionRequest(r); err != nil {
		return nil, h.deny()
	}
	return r, nil
}

// Query borrows bounded primary reads. Check and eligibility phases use only
// read/locking SQL. Ownership/lifetime remain with the enclosing kernel Work.
func (h AccountUnlinkWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	rows, err := h.state.work.Query(ctx, sql, args...)
	return rows, h.failure(ctx, err)
}

// Exec borrows provisional writes only during persistence or finalization.
func (h AccountUnlinkWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	if ctx == nil || h.state.phase != accountUnlinkPersist && h.state.phase != accountUnlinkFinalize {
		return 0, h.deny()
	}
	n, err := h.state.work.Exec(ctx, sql, args...)
	return n, h.failure(ctx, err)
}

// DatabaseTime samples the original primary transaction's clock; it cannot
// renew proof, session, risk or current-authority evidence deadlines.
func (h AccountUnlinkWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.DatabaseTime(ctx)
	return now, h.failure(ctx, err)
}

// RequireActiveCredential retains the actual credential and authority fences
// in this original transaction. Only the invoked unlink owner may select it;
// the expected admission must come from the genuine original password/session
// owner, not from enabled credential-reference rows.
func (h AccountUnlinkWork) RequireActiveCredential(ctx context.Context, owner AccountUnlinkContributor, expected CredentialAdmission) (time.Time, error) {
	spec, _, err := h.Command(owner)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	return h.state.work.requireActiveCredential(ctx, spec.Binding, expected)
}

// RequireActiveDirectoryAuthority retains the original directory epoch locks.
// It supplies no new session, proof, snapshot or renewed validity evidence.
func (h AccountUnlinkWork) RequireActiveDirectoryAuthority(ctx context.Context, owner AccountUnlinkContributor, expected DirectoryAuthorityAdmission) error {
	spec, _, err := h.Command(owner)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveDirectoryAuthority(ctx, spec.Binding, expected)
}

// RequireActiveUserAuthorization retains the original primary policy epoch.
// The trusted owner separately evaluates policy and propagates every denial.
func (h AccountUnlinkWork) RequireActiveUserAuthorization(ctx context.Context, owner AccountUnlinkContributor, expected UserAuthorizationAdmission) error {
	spec, _, err := h.Command(owner)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveUserAuthorization(ctx, spec.Binding, expected)
}
