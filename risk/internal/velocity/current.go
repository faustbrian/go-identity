package velocity

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-identity/risk"
)

// CurrentChain is the original acknowledged activation, not a new authority.
// Only owned adapters can name this internal type. Native composition receives
// it from the journal connection, never independently from application input.
// Copies preserve every original receipt and its primary checker; no issuance
// capability, mutable health cache, timestamp or pool identifier is retained.
type CurrentChain struct {
	Lease        risk.VelocityLease
	Closure      risk.VelocityClosure
	Publication  risk.VelocityPublication
	Confirmation risk.VelocityConfirmation
	Native       risk.VelocityNativeConfirmation
	Eligibility  risk.VelocityEligibility
}

type currentChain struct {
	reader risk.VelocityJournalVerifier
	chain  CurrentChain
}

// BindCurrentJournal retains the concrete primary owner's original chain after
// exact graph/namespace authentication and a current-primary read. j's callbacks
// and chain must originate in the same concrete recovery owner. There are no
// application binders; adapters must enforce that invariant in their factory.
// Already-bound or invalid connections deny without replacing original custody.
// The original connection remains unchanged; transactions end in its callbacks.
func BindCurrentJournal(ctx context.Context, j Journal, reader risk.VelocityJournalVerifier, verifier risk.VelocityNativeVerifier, chain CurrentChain) (Journal, error) {
	if j.state == nil || j.state.current != nil {
		return Journal{}, risk.ErrInvalidVelocityRecovery
	}
	l, err := reader.Lease(chain.Lease)
	if err != nil || l.Namespace != j.state.namespace {
		return Journal{}, risk.ErrInvalidVelocityRecovery
	}
	if _, err := verifier.Eligibility(ctx, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native, chain.Eligibility); err != nil {
		return Journal{}, err
	}
	b := *j.state
	b.current = &currentChain{reader: reader, chain: chain}
	return Journal{state: &b}, nil
}

// Current authenticates only this native owner's configured read-only journal
// view, then checks current primary eligibility on the retained exact chain.
// Foreign/zero graph and missing custody deny before primary IO. It invokes no
// replay-only callbacks and grants no native IO, mutation or retry permission.
// Package-function visibility prevents applications holding inferred opaque
// outputs from extracting this custody through an exported handle method.
func Current(ctx context.Context, j Journal, issuer risk.VelocityNativeIssuer) (CurrentChain, error) {
	if j.state == nil || j.state.current == nil {
		return CurrentChain{}, risk.ErrInvalidVelocityRecovery
	}
	r, err := issuer.JournalVerifier()
	if err != nil || r != j.state.current.reader {
		return CurrentChain{}, risk.ErrInvalidVelocityRecovery
	}
	v, err := issuer.Verifier()
	if err != nil {
		return CurrentChain{}, err
	}
	c := j.state.current.chain
	if _, err := v.Eligibility(ctx, c.Lease, c.Closure, c.Publication, c.Confirmation, c.Native, c.Eligibility); err != nil {
		return CurrentChain{}, err
	}
	return c, nil
}

// BindCurrentNative binds owned native functions to the exact journal connection
// from which their activated chain was obtained. Current primary state is read
// before construction and each native check. check/mutate must additionally
// enforce concrete transport continuity and the exact native marker; mutate
// independently checks current custody at its atomic effect boundary. This
// function owns no transport, issuance, goroutine, clock, lock or transaction.
func BindCurrentNative(ctx context.Context, j Journal, issuer risk.VelocityNativeIssuer, validate func(risk.CounterCommand) error, check func(context.Context, risk.CounterCommand) error, mutate func(context.Context, risk.CounterCommand) (risk.CounterResult, error)) (Native, error) {
	if validate == nil || check == nil || mutate == nil {
		return Native{}, risk.ErrInvalidVelocityRecovery
	}
	if _, err := Current(ctx, j, issuer); err != nil {
		return Native{}, err
	}
	n, err := BindNative(j.state.namespace, validate, func(checkCtx context.Context, c risk.CounterCommand) error {
		if _, err := Current(checkCtx, j, issuer); err != nil {
			return err
		}
		return check(checkCtx, c)
	}, mutate)
	if err != nil {
		return Native{}, err
	}
	n.state.journal = j.state
	return n, nil
}

func (CurrentChain) Format(s fmt.State, _ rune)   { redact(s) }
func (CurrentChain) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (CurrentChain) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
