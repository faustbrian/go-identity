package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// AccountLinkPreparationContributor extends the exact native provider/session
// owner for original root OAuth callback intent, not a feature command.
// Validation is bounded and I/O-free. Admission borrows primary read/authority
// checks only: no mutation, external callbacks, decryption, exchange or signing.
// Generate runs outside SQL only after the coordinator acknowledges durable
// original-state reservation and its generation marker. It returns bounded
// authenticated ciphertext, never plaintext credentials. Restore authenticates
// the unchanged original intent, original output generation and submitted bearer
// without SQL, network, generation or expiry renewal. It returns the exact final
// signed command, consuming plan and one matching issuance declaration.
// The existing issuer must persist that grant during attachment; issuance is
// preparation evidence, never proof that the protected account link committed.
// Shared owners support concurrent independent calls with invocation-local state.
type AccountLinkPreparationContributor interface {
	AccountLinkContributor
	ValidateAccountLinkPreparation(identity.Command, CommandPlan) error
	AdmitAccountLinkPreparation(context.Context, AccountLinkPreparationWork, identity.Command) error
	GenerateAccountLinkPreparation(context.Context, identity.Command, uint64) ([]byte, error)
	RestoreAccountLinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error)
}

func (c *Coordinator) prepareAccountLinkPreparation(original identity.Command, declaration CommandPlan) (q claimRequest, admitted *admittedKernelPlan, owner AccountLinkPreparationContributor, err error) {
	defer func() {
		if recover() != nil {
			q, admitted, owner, err = claimRequest{}, nil, nil, invalidPreparation()
		}
	}()
	spec, _, _, ok := original.AccountLinkPreparationInput()
	if !ok || c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 || !accountLinkBinding(spec.Binding) || declaration.AccountLinkState == nil || declaration.Capability != nil {
		return q, nil, nil, invalidPreparation()
	}
	q, err = prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, err := encodeKernelPlan(spec.Binding, fp, declaration)
	if err != nil {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	owned, err := decodeKernelPlan(spec.Binding, fp, wire)
	if err != nil {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	admitted, err = c.registry.admitKernelPlanMode(spec.Binding, fp, owned, true)
	if err != nil || admitted.accountLink == nil {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	owner, ok = admitted.accountLink.contributor.(AccountLinkPreparationContributor)
	if !ok || owner.ValidateAccountLinkPreparation(original, admitted.snapshot()) != nil || validateCommandCounters(counterAdmissionParticipant(admitted), original, *admitted.counters) != nil {
		return claimRequest{}, nil, nil, invalidPreparation()
	}
	return q, admitted, owner, nil
}

type accountLinkPreparationInvocation struct {
	work     Work
	owner    AccountLinkPreparationContributor
	original identity.Command
	active   bool
}

// AccountLinkPreparationWork borrows primary admission reads from the sole
// coordinator transaction before its durable start. There is no constructor,
// Exec, raw transaction, commit, generation or provider-call authority. Copies
// share serial invocation lifetime and failure state; returned handles deny.
// Query is trusted bounded read/locking SQL, not an untrusted SQL sandbox.
// Close every cursor before returning and propagate every denied authority.
type AccountLinkPreparationWork struct {
	state *accountLinkPreparationInvocation
}

// Format hides original callback, session and transaction correlations.
func (AccountLinkPreparationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountLinkPreparationWork(redacted)"))
}

// MarshalJSON refuses serialization of borrowed admission authority.
func (AccountLinkPreparationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText refuses serialization of borrowed admission authority.
func (AccountLinkPreparationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h AccountLinkPreparationWork) usable() error {
	if h.state == nil || !h.state.active || h.state.work.usable() != nil || h.state.work.state.execution == nil {
		return invalidWork()
	}
	e := h.state.work.state.execution
	if !e.coordinator.owns(h.state.work) || e.reservation.plan == nil || e.reservation.plan.accountLink == nil || e.reservation.plan.accountLinkState == nil || e.reservation.plan.capability != nil || e.reservation.executionRequest != nil || e.reservation.preparation != nil || !sameParticipant(e.reservation.plan.accountLink.contributor, h.state.owner) {
		return invalidWork()
	}
	return nil
}

func (h AccountLinkPreparationWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}

// Command returns original metadata only to the exact invoked owner. It creates
// neither a provider subject nor signed proof and exposes no callback secret.
func (h AccountLinkPreparationWork) Command(p AccountLinkPreparationContributor) (identity.AccountLinkPreparationCommand, error) {
	if err := h.usable(); err != nil {
		return identity.AccountLinkPreparationCommand{}, err
	}
	s, _, _, ok := h.state.original.AccountLinkPreparationInput()
	if !ok || s.Binding != h.state.work.state.binding || !sameParticipant(p, h.state.owner) {
		return identity.AccountLinkPreparationCommand{}, h.deny()
	}
	return s, nil
}

// Query borrows bounded primary read/locking SQL for this admission only.
func (h AccountLinkPreparationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	return h.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary time without renewing original admission facts.
func (h AccountLinkPreparationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	return h.state.work.DatabaseTime(ctx)
}

// RequireActiveCredential reuses the kernel's current credential/epoch fence.
func (h AccountLinkPreparationWork) RequireActiveCredential(ctx context.Context, p AccountLinkPreparationContributor, expected CredentialAdmission) (time.Time, error) {
	s, err := h.Command(p)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	return h.state.work.requireActiveCredential(ctx, s.Binding, expected)
}

// RequireActiveDirectoryAuthority reuses the kernel's exact directory fence.
func (h AccountLinkPreparationWork) RequireActiveDirectoryAuthority(ctx context.Context, p AccountLinkPreparationContributor, expected DirectoryAuthorityAdmission) error {
	s, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveDirectoryAuthority(ctx, s.Binding, expected)
}

// RequireActiveUserAuthorization reuses the original user-policy epoch fence.
func (h AccountLinkPreparationWork) RequireActiveUserAuthorization(ctx context.Context, p AccountLinkPreparationContributor, expected UserAuthorizationAdmission) error {
	s, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.state.work.requireActiveUserAuthorization(ctx, s.Binding, expected)
}
