package postgres

import (
	"bytes"
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// AccountLinkCleanupContributor erases its original RP exchange secrets on a
// known terminal refusal. The coordinator invokes it before exchange on counter
// denial or after proven domain rollback. Cleanup, audit, proof release and the
// refusal receipt share the existing fenced transaction. It must not exchange,
// change identity, issue authority or infer success. Errors roll back this
// terminal transaction; external exchange uncertainty never selects cleanup.
// Optional for ordinary link owners without recoverable RP exchange secrets.
type AccountLinkCleanupContributor interface {
	AccountLinkPreparationContributor
	CleanupAccountLink(context.Context, AccountLinkCleanupWork) error
}

type accountLinkCleanupInvocation struct {
	work    Work
	owner   AccountLinkCleanupContributor
	binding identity.CommandBinding
	state   CapabilityPlan
	active  bool
}

// AccountLinkCleanupWork borrows only terminal erasure authority. Original
// callback metadata and state-plan identity remain authenticated by the command
// claim; no currently usable execution proof is needed to erase failed custody.
// There is no constructor, raw transaction, exchange or commit access. Copies
// share serial invocation lifetime; zero, foreign and returned handles deny.
type AccountLinkCleanupWork struct{ state *accountLinkCleanupInvocation }

// Format hides callback, session and transaction correlations.
func (AccountLinkCleanupWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountLinkCleanupWork(redacted)"))
}

// MarshalJSON refuses serialization of terminal authority.
func (AccountLinkCleanupWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText refuses serialization of terminal authority.
func (AccountLinkCleanupWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h AccountLinkCleanupWork) usable() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.usable()
}

// Scope returns the original binding and state identity to its exact invoked
// owner. Historical recovery needs neither callback custody nor a live proof;
// this metadata grants only erasure of the exact failed RP transaction.
func (h AccountLinkCleanupWork) Scope(owner AccountLinkCleanupContributor) (identity.CommandBinding, CapabilityPlan, error) {
	if err := h.usable(); err != nil {
		return identity.CommandBinding{}, CapabilityPlan{}, err
	}
	if !sameParticipant(owner, h.state.owner) {
		return identity.CommandBinding{}, CapabilityPlan{}, h.state.work.fail(h.state.work.state.ctx, invalidWork())
	}
	return h.state.binding, h.state.state, nil
}

// Exec permits bounded trusted SQL for this owner's erasure in the terminal
// transaction. It is not an application SQL sandbox or independent writer.
func (h AccountLinkCleanupWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	if ctx == nil {
		return 0, h.state.work.fail(h.state.work.state.ctx, invalidWork())
	}
	return h.state.work.Exec(ctx, sql, args...)
}

func (c *Coordinator) cleanupPreparedAccountLink(ctx context.Context, w Work) (err error) {
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	r := w.state.execution.reservation
	if r.plan == nil || r.plan.accountLink == nil || r.plan.accountLinkState == nil {
		return nil
	}
	owner, ok := r.plan.accountLink.contributor.(AccountLinkCleanupContributor)
	if !ok {
		return nil
	}
	binding, feature, err := decodeObservedScope(r.request.safeFields)
	if err != nil || feature != nil || binding != w.state.binding || binding != r.plan.binding {
		return w.fail(ctx, invalidPreparation())
	}
	if r.request.source != nil {
		original := *r.request.source
		q, err := prepareClaim(original, c.keys.retained[c.keys.current])
		spec, _, _, ok := original.AccountLinkPreparationInput()
		if err != nil || !bytes.Equal(q.canonical, r.request.canonical) || !ok || spec.Binding != binding {
			return w.fail(ctx, invalidPreparation())
		}
	}
	s := &accountLinkCleanupInvocation{work: w, owner: owner, binding: binding, state: *r.plan.accountLinkState, active: true}
	defer func() {
		s.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err = owner.CleanupAccountLink(ctx, AccountLinkCleanupWork{state: s}); err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
