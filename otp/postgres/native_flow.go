package postgres

import (
	"context"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Exactly one original variant is restored from authenticated custody. Session
// state is read-only: unlike pre-auth it is never reserved or consumed by OTP.
type nativeFlow struct {
	preauth session.PreAuthTransaction
	session session.Session
}

func (p *Contributor) authenticateFlow(ctx context.Context, command identity.Command, plan kernel.OTPAttemptPlan) (nativeFlow, error) {
	spec, ok := command.Feature()
	if !ok {
		return nativeFlow{}, ErrInvalidCommand
	}
	if token, ok := command.SessionToken(); ok {
		return p.authenticateFlowSpec(ctx, spec, plan, token)
	}
	cookie, ok := command.PreAuthCookie()
	if !ok {
		return nativeFlow{}, ErrInvalidCommand
	}
	return p.authenticateFlowSpec(ctx, spec, plan, cookie)
}

func (p *Contributor) authenticateFlowSpec(ctx context.Context, spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan, submitted auth.BearerCredential) (nativeFlow, error) {
	if p == nil || p.codec == nil {
		return nativeFlow{}, ErrInvalidCommand
	}
	c, err := p.codec.restoreCustody(spec)
	if err != nil || c.authority == nil {
		return nativeFlow{}, ErrInvalidCommand
	}
	f, err := retainedNativeFlow(c)
	if err != nil {
		return nativeFlow{}, err
	}
	if f.session != (session.Session{}) {
		if p.session == nil {
			return nativeFlow{}, ErrInvalidCommand
		}
		original, err := p.codec.authenticateSessionSpec(ctx, p.session.keys, spec, plan, submitted)
		if err != nil {
			return nativeFlow{}, err
		}
		if p.sessionAuthority(original, spec.Binding, *c.authority) != nil {
			return nativeFlow{}, ErrInvalidCommand
		}
		return nativeFlow{session: original}, nil
	}
	original, err := p.codec.authenticatePreAuthSpec(ctx, p.preauth, spec, plan, submitted)
	if err != nil {
		return nativeFlow{}, err
	}
	return nativeFlow{preauth: original}, nil
}

func retainedNativeFlow(c nativeCustody) (nativeFlow, error) {
	b, err := c.record.Attempt.Continuation.Bindings()
	if err != nil {
		return nativeFlow{}, ErrInvalidCommand
	}
	if original, ok := b.Authorization.AuthenticatedSession(); ok {
		return nativeFlow{session: original}, nil
	}
	if original, ok := b.Authorization.PreAuthTransaction(); ok {
		return nativeFlow{preauth: original}, nil
	}
	return nativeFlow{}, ErrInvalidCommand
}

func requireNativeFlow[R sessionpg.SessionRows](ctx context.Context, q sessionpg.SessionQueryer[R], p *Contributor, flow nativeFlow, use *sessionpg.PreAuthUse) error {
	if flow.session != (session.Session{}) {
		if p.session == nil {
			return ErrInvalidCommand
		}
		return sessionpg.RequireSession(ctx, q, p.session.store, flow.session)
	}
	if p.preauth == nil || flow.preauth == (session.PreAuthTransaction{}) {
		return ErrInvalidCommand
	}
	if use == nil {
		return sessionpg.RequirePreAuth(ctx, q, p.preauth.config, flow.preauth)
	}
	return sessionpg.RequireReservedPreAuth(ctx, q, p.preauth.config, flow.preauth, *use)
}

func reserveNativeFlow[R sessionpg.SessionRows](ctx context.Context, q sessionpg.PreAuthWriter[R], p *Contributor, flow nativeFlow, b kernel.OTPReservationBinding) error {
	if flow.session != (session.Session{}) {
		return requireNativeFlow(ctx, q, p, flow, nil)
	}
	if p.preauth == nil {
		return ErrInvalidCommand
	}
	if b.PreviousGeneration != 0 {
		return sessionpg.RebindPreAuth(ctx, q, p.preauth.config, flow.preauth, sessionpg.PreAuthUse{Command: b.Command, Fingerprint: b.Fingerprint, Generation: b.PreviousGeneration}, b.Generation)
	}
	return sessionpg.ReservePreAuth(ctx, q, p.preauth.config, flow.preauth, sessionpg.PreAuthUse{Command: b.Command, Fingerprint: b.Fingerprint, Generation: b.Generation})
}

func (p *Contributor) flowTime(flow nativeFlow, now time.Time) error {
	if flow.session != (session.Session{}) {
		return p.sessionTime(flow.session, now)
	}
	s, err := flow.preauth.Bindings()
	if err != nil || flow.preauth.Check(now, s.Binding, s.Cookie) != nil {
		return ErrInvalidCommand
	}
	return nil
}
