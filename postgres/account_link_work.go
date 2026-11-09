package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// AccountLinkContributor is the trusted native provider/session policy owner
// for explicit self-linking. Preparation performs bounded primary reads only;
// provider exchange belongs to acknowledged native preparation outside SQL.
// Validation reconstructs the exact retained provider, session, policy and risk
// input without I/O. Check repeats current admission initially and before final
// consumption. Persist and Finalize write only this owner's provisional effects
// in the kernel's transaction. No phase may open or close a transaction, run
// network callbacks, retain handles, refresh proof expiry or substitute identity
// link rows. Recovery must preserve uncertainty about external exchange effects.
type AccountLinkContributor interface {
	RecoveryContributor
	PrepareAccountLink(context.Context, identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error)
	ValidateAccountLink(identity.Command, CommandPlan) error
	CheckAccountLink(context.Context, AccountLinkWork) error
	PersistAccountLink(context.Context, AccountLinkWork) error
	FinalizeAccountLink(context.Context, AccountLinkWork) error
}

type accountLinkPhase uint8

const (
	accountLinkCheck accountLinkPhase = iota + 1
	accountLinkPersist
	accountLinkFinalCheck
	accountLinkFinalize
)

type accountLinkInvocation struct {
	work        Work
	participant AccountLinkContributor
	command     identity.AccountLinkCommand
	phase       accountLinkPhase
	active      bool
}

// Progress is local to one Work and cannot be supplied by a callback or replay.
type accountLinkProgress struct {
	command                                               identity.Command
	user                                                  identity.User
	receipt                                               identity.AccountLinkReceipt
	initial, persisted, applied, final, finalized, active bool
}

// AccountLinkWork borrows the original transaction only during the selected
// native invocation. Copies share serial lifetime and error state; zero,
// foreign and retained handles deny. Queries are bounded trusted SQL, not a
// caller SQL sandbox. Only persistence/finalization permits Exec. Close every
// cursor before returning. This handle grants no independent commit authority.
type AccountLinkWork struct{ state *accountLinkInvocation }

// Format hides command, provider, proof and transactional correlation.
func (AccountLinkWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountLinkWork(redacted)"))
}

// MarshalJSON rejects export of invocation authority.
func (AccountLinkWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit export of invocation authority.
func (AccountLinkWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h AccountLinkWork) usable() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.usable()
}

func (h AccountLinkWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}

func (h AccountLinkWork) failure(ctx context.Context, err error) error {
	if err != nil {
		return h.state.work.fail(ctx, err)
	}
	return nil
}

// Command returns original signed intent to the exact native participant. The
// boolean identifies the terminal check/finalization, never renewed freshness.
func (h AccountLinkWork) Command(p AccountLinkContributor) (identity.AccountLinkCommand, bool, error) {
	if err := h.usable(); err != nil {
		return identity.AccountLinkCommand{}, false, err
	}
	if !sameParticipant(p, h.state.participant) {
		return identity.AccountLinkCommand{}, false, h.deny()
	}
	// Reconstruct an owned copy through the root constructor/getter. A native
	// callback cannot mutate the retained method pointer through its result.
	c, err := identity.NewAccountLinkCommand(h.state.command)
	if err != nil {
		return identity.AccountLinkCommand{}, false, h.deny()
	}
	spec, _ := c.LinkAccount()
	return spec, h.state.phase == accountLinkFinalCheck || h.state.phase == accountLinkFinalize, nil
}

// Preparation lends the exact original typed callback/session input, an owned
// copy of retained authenticated ciphertext and its original generation only to
// the currently invoked native preparation owner. It permits local restoration
// and current checks, never exchange, generation or freshness renewal. Callback
// custody retains its shared bounded lifetime; do not destroy it before the
// enclosing operation returns. No SQL, callbacks or raw transaction escape run.
// Ordinary links, foreign owners, zero and returned invocations deny.
func (h AccountLinkWork) Preparation(p AccountLinkPreparationContributor) (identity.Command, []byte, uint64, error) {
	if _, _, err := h.Command(p); err != nil {
		return identity.Command{}, nil, 0, err
	}
	e := h.state.work.state.execution
	if e == nil || e.coordinator == nil || e.reservation == nil || !e.coordinator.owns(h.state.work) || e.reservation.coordinator != e.coordinator || e.reservation.plan == nil || e.reservation.plan.accountLinkState == nil || e.reservation.request.source == nil {
		return identity.Command{}, nil, 0, h.deny()
	}
	r := e.reservation
	if _, err := accountLinkExecutionRequest(r); err != nil {
		return identity.Command{}, nil, 0, h.deny()
	}
	return *r.request.source, bytes.Clone(r.preparation.ciphertext), r.preparation.generation, nil
}

// Query borrows bounded primary reads. Check phases must use read/locking SQL,
// not mutations; the native implementation is a trusted owner, not a sandbox.
func (h AccountLinkWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	rows, err := h.state.work.Query(ctx, sql, args...)
	return rows, h.failure(ctx, err)
}

// Exec borrows provisional writes during persistence or finalization.
func (h AccountLinkWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	if ctx == nil || h.state.phase != accountLinkPersist && h.state.phase != accountLinkFinalize {
		return 0, h.deny()
	}
	n, err := h.state.work.Exec(ctx, sql, args...)
	return n, h.failure(ctx, err)
}

// DatabaseTime reads primary time without renewing the original proof/session.
func (h AccountLinkWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.DatabaseTime(ctx)
	return now, h.failure(ctx, err)
}

// RequireActiveCredential checks and locks the exact original credential and
// independent user epochs using the existing kernel authority implementation.
func (h AccountLinkWork) RequireActiveCredential(ctx context.Context, p AccountLinkContributor, expected CredentialAdmission) (time.Time, error) {
	c, _, err := h.Command(p)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.requireActiveCredential(ctx, c.Binding, expected)
	return now, h.failure(ctx, err)
}

// RequireActiveDirectoryAuthority locks and checks exact global/tenant epochs.
func (h AccountLinkWork) RequireActiveDirectoryAuthority(ctx context.Context, p AccountLinkContributor, expected DirectoryAuthorityAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveDirectoryAuthority(ctx, c.Binding, expected))
}

// RequireActiveUserAuthorization checks original user-authorization authority.
func (h AccountLinkWork) RequireActiveUserAuthorization(ctx context.Context, p AccountLinkContributor, expected UserAuthorizationAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveUserAuthorization(ctx, c.Binding, expected))
}

// CredentialAuthorityVersion returns the original epoch during initial
// admission and only this Work's persisted successor during terminal checks.
// It cannot adopt a newer external epoch or renew original session freshness.
func (h AccountLinkWork) CredentialAuthorityVersion(p AccountLinkContributor) (uint64, error) {
	c, final, err := h.Command(p)
	if err != nil {
		return 0, err
	}
	if !final {
		return c.Change.ExpectedCredentialVersion, nil
	}
	progress := h.state.work.state.accountLink
	if progress == nil || !progress.applied || progress.finalized || progress.receipt.ExpectedCredentialVersion != c.Change.ExpectedCredentialVersion || progress.receipt.AccountID != c.Change.Account.ID || progress.user.Version != c.Change.ExpectedUserVersion+1 {
		return 0, h.deny()
	}
	return progress.receipt.CredentialVersion, nil
}

func (c *Coordinator) runAccountLinkPhase(ctx context.Context, w Work, command identity.Command, phase accountLinkPhase) (err error) {
	if !c.owns(w) {
		return invalidWork()
	}
	if err = w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	r := w.state.execution.reservation
	p := r.plan
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || p == nil || p.accountLink == nil || spec.Binding != p.binding || spec.Binding != w.state.binding {
		return w.fail(ctx, invalidPlan())
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	expected, expectedErr := accountLinkExecutionRequest(r)
	if err != nil || expectedErr != nil || !bytes.Equal(q.canonical, expected.canonical) {
		return w.fail(ctx, invalidPlan())
	}
	owner, ok := p.accountLink.contributor.(AccountLinkContributor)
	if !ok || !sameParticipant(owner, owner) {
		return w.fail(ctx, invalidPlan())
	}
	progress := w.state.accountLink
	if phase == accountLinkCheck {
		if progress != nil {
			return w.fail(ctx, invalidWork())
		}
		progress = &accountLinkProgress{command: command}
		w.state.accountLink = progress
	} else if progress == nil || progress.active || !progress.initial || progress.finalized {
		return w.fail(ctx, invalidWork())
	}
	switch phase {
	case accountLinkCheck:
	case accountLinkPersist:
		if progress.persisted || progress.applied || progress.final {
			return w.fail(ctx, invalidWork())
		}
	case accountLinkFinalCheck:
		if !progress.persisted || !progress.applied || progress.final {
			return w.fail(ctx, invalidWork())
		}
	case accountLinkFinalize:
		if !progress.persisted || !progress.applied || !progress.final {
			return w.fail(ctx, invalidWork())
		}
	default:
		return w.fail(ctx, invalidWork())
	}
	progress.active = true
	s := &accountLinkInvocation{work: w, participant: owner, command: spec, phase: phase, active: true}
	defer func() {
		s.active, progress.active = false, false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	switch phase {
	case accountLinkCheck, accountLinkFinalCheck:
		err = owner.CheckAccountLink(ctx, AccountLinkWork{state: s})
	case accountLinkPersist:
		err = owner.PersistAccountLink(ctx, AccountLinkWork{state: s})
	case accountLinkFinalize:
		err = owner.FinalizeAccountLink(ctx, AccountLinkWork{state: s})
	}
	if err != nil {
		_, _, _, safe := abortClassification(err)
		return w.fail(ctx, safe)
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	if err = w.usable(); err != nil {
		return err
	}
	switch phase {
	case accountLinkCheck:
		progress.initial = true
	case accountLinkPersist:
		progress.persisted = true
	case accountLinkFinalCheck:
		progress.final = true
	case accountLinkFinalize:
		progress.finalized = true
	}
	return nil
}
