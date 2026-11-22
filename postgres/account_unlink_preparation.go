package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// AccountUnlinkPreparationContributor extends the actual unlink owner with
// original password/session admission and retained child-grant preparation.
// Validation is bounded and I/O-free. Admission performs only primary reads and
// current-authority checks; it must not consume the password proof. Generate
// runs outside SQL only after acknowledged original journal reservation. Restore
// authenticates original intent and encrypted output without new signing,
// entropy or freshness renewal. The existing issuer persists/reserves the exact
// child during attachment; that row is not positive unlink recovery evidence.
// Actual password-proof consumption remains atomic with the final mutation.
// Independent calls use invocation-local state; no borrowed Work may escape.
type AccountUnlinkPreparationContributor interface {
	AccountUnlinkContributor
	ValidateAccountUnlinkPreparation(identity.Command, CommandPlan) error
	AdmitAccountUnlinkPreparation(context.Context, AccountUnlinkPreparationWork, identity.Command) error
	GenerateAccountUnlinkPreparation(context.Context, identity.Command, uint64) ([]byte, error)
	RestoreAccountUnlinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error)
}

func (c *Coordinator) prepareAccountUnlinkPreparation(original identity.Command, declaration CommandPlan) (q claimRequest, admitted *admittedKernelPlan, owner AccountUnlinkPreparationContributor, err error) {
	fail := func() (claimRequest, *admittedKernelPlan, AccountUnlinkPreparationContributor, error) {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	defer func() {
		if recover() != nil {
			q, admitted, owner, err = fail()
		}
	}()
	spec, _, ok := original.AccountUnlinkPreparationInput()
	if !ok || c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 {
		return fail()
	}
	if !accountUnlinkBinding(spec.Binding) || spec.RevokeProvider || declaration.Capability != nil || declaration.AccountLinkState != nil || declaration.Lifecycle == nil {
		return fail()
	}
	if declaration.Lifecycle.BeforeVersion != spec.Change.ExpectedAccountVersion || declaration.Lifecycle.AfterVersion != spec.Change.ExpectedAccountVersion+1 {
		return fail()
	}
	q, err = prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) {
		return fail()
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, err := encodeKernelPlan(spec.Binding, fp, declaration)
	if err != nil {
		return fail()
	}
	owned, err := decodeKernelPlan(spec.Binding, fp, wire)
	if err != nil {
		return fail()
	}
	admitted, err = c.registry.admitKernelPlanMode(spec.Binding, fp, owned, true)
	if err != nil || admitted.accountUnlink == nil || admitted.counters == nil {
		return fail()
	}
	owner, ok = admitted.accountUnlink.contributor.(AccountUnlinkPreparationContributor)
	if !ok || owner.ValidateAccountUnlinkPreparation(original, admitted.snapshot()) != nil {
		return fail()
	}
	if validateCommandCounters(counterAdmissionParticipant(admitted), original, *admitted.counters) != nil {
		return fail()
	}
	return q, admitted, owner, nil
}

type accountUnlinkPreparationInvocation struct {
	work     Work
	owner    AccountUnlinkPreparationContributor
	original identity.Command
	active   bool
}

// AccountUnlinkPreparationWork lends bounded primary admission reads before
// durable generation starts. It exposes neither Exec nor a raw transaction,
// closure, signing, mutation or proof consumption. Query is trusted read/locking
// SQL, not a SQL sandbox. Close cursors and propagate every denied authority.
// Copies share serial invocation lifetime and failure state; retained handles
// and foreign same-descriptor participants deny.
type AccountUnlinkPreparationWork struct {
	state *accountUnlinkPreparationInvocation
}

// Format omits session, proof and transaction correlations.
func (AccountUnlinkPreparationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountUnlinkPreparationWork(redacted)"))
}

// MarshalJSON rejects export of borrowed authority.
func (AccountUnlinkPreparationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit text export of borrowed authority.
func (AccountUnlinkPreparationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h AccountUnlinkPreparationWork) usable() error {
	if h.state == nil || !h.state.active || h.state.work.usable() != nil || h.state.work.state.execution == nil {
		return invalidWork()
	}
	e := h.state.work.state.execution
	if !e.coordinator.owns(h.state.work) || e.reservation.plan == nil {
		return invalidWork()
	}
	p := e.reservation.plan
	if p.accountUnlink == nil || p.capability != nil || e.reservation.executionRequest != nil || e.reservation.preparation != nil || !sameParticipant(p.accountUnlink.contributor, h.state.owner) {
		return invalidWork()
	}
	return nil
}

func (h AccountUnlinkPreparationWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}

// Command returns independently owned original metadata to the invoked owner.
// It authenticates no password/session and creates no signed child grant.
func (h AccountUnlinkPreparationWork) Command(p AccountUnlinkPreparationContributor) (identity.AccountUnlinkPreparationCommand, error) {
	if err := h.usable(); err != nil {
		return identity.AccountUnlinkPreparationCommand{}, err
	}
	spec, _, ok := h.state.original.AccountUnlinkPreparationInput()
	if !ok || spec.Binding != h.state.work.state.binding || !sameParticipant(p, h.state.owner) {
		return identity.AccountUnlinkPreparationCommand{}, h.deny()
	}
	return spec, nil
}

// Query lends bounded read/locking SQL for this admission only.
func (h AccountUnlinkPreparationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	return h.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary time without renewing original proof freshness.
func (h AccountUnlinkPreparationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	return h.state.work.DatabaseTime(ctx)
}

// RequireActiveCredential uses the kernel's actual current credential fence.
func (h AccountUnlinkPreparationWork) RequireActiveCredential(ctx context.Context, p AccountUnlinkPreparationContributor, expected CredentialAdmission) (time.Time, error) {
	spec, err := h.Command(p)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	return h.state.work.requireActiveCredential(ctx, spec.Binding, expected)
}

// RequireActiveDirectoryAuthority retains the original directory epoch fence.
func (h AccountUnlinkPreparationWork) RequireActiveDirectoryAuthority(ctx context.Context, p AccountUnlinkPreparationContributor, expected DirectoryAuthorityAdmission) error {
	spec, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveDirectoryAuthority(ctx, spec.Binding, expected)
}

// RequireActiveUserAuthorization uses the original user-policy epoch fence.
func (h AccountUnlinkPreparationWork) RequireActiveUserAuthorization(ctx context.Context, p AccountUnlinkPreparationContributor, expected UserAuthorizationAdmission) error {
	spec, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveUserAuthorization(ctx, spec.Binding, expected)
}
