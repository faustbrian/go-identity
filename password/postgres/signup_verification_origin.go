package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// ReadRegistrationVerification authenticates the signed, durably issued signup
// proof and original encrypted signup input, then authorizes their exact email
// intent. caller is the actual current confirmation caller, with action
// identity.email.verification-confirm, identity.user target equal to the signed
// subject, and the current query policy revision. Never supply the signup actor
// or infer session authority from this anonymous registration profile.
//
// This is a trusted native workflow seam, not a public Validate result: the
// returned spec contains sensitive mailbox, redirect and historical correlation.
// It must not be logged or disclosed. The replay version is the original retained
// issuer version, not the active key. Confirmation still owns primary current
// account/identifier and capability checks and atomic mutation/consumption.
// Historical provenance, including a previously consumed grant, grants no use.
//
// No live pre-auth flow, cookie, password, signing, reservation, mutation or
// session is needed or produced. The primary pool and proof remain borrowed;
// calls own their temporary ciphertext, clear it on every path and are bounded
// by Repository.MaximumDuration and earlier cancellation. Immutable composition
// supports concurrent reads and owns no goroutines. Every failure returns zero
// sensitive projection with redacted typed errors; cancellation is preserved.
func (s *SignupService) ReadRegistrationVerification(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (spec email.RegistrationVerificationSpec, replayVersion uint32, err error) {
	spec, replayVersion, _, err = s.readRegistrationVerification(ctx, proof, caller)
	return
}

// The optional original-browser signin profile also needs the authenticated
// encrypted flow, not a caller-supplied remember choice or a live flow lookup.
func (s *SignupService) readRegistrationVerification(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (spec email.RegistrationVerificationSpec, replayVersion uint32, original session.PreAuthTransaction, err error) {
	if ctx == nil || s == nil || s.config == nil || s.repository == nil || s.crypto == nil || s.pool == nil {
		return spec, 0, original, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			spec, replayVersion, original = email.RegistrationVerificationSpec{}, 0, session.PreAuthTransaction{}
		}
	}()
	if ctx.Err() != nil {
		return spec, 0, original, ctx.Err()
	}
	grant, command, version, err := c.Verification.Issuer.ReadRegistrationOrigin(ctx, s.pool, proof)
	if err != nil {
		return spec, 0, original, err
	}
	g := grant.Payload()
	p := &signupPhase{service: s}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return spec, 0, original, password.ErrPasswordWork
	}
	q := identity.RecoveryQuery{CommandID: command, TenantID: identity.TenantID(g.Tenant), UserID: identity.UserID(g.Subject), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: "identity.email.verification-confirm"}
	k, wire, err := coordinator.QueryRegistrationPreparation(ctx, q, caller, p.registration(), p)
	defer clear(wire)
	if err != nil {
		return spec, 0, original, err
	}
	b, selected, flow, at, err := s.repository.recoverSignupInput(ctx, s.crypto, k, s.profile, wire)
	if err != nil || b.CommandID != command || b.TenantID != q.TenantID || selected.Creation.Binding.UserID != q.UserID {
		return spec, 0, original, readerFailure(ctx)
	}
	spec, err = signupVerificationSpec(b, selected, flow, at, signupVerificationPreparation{address: c.Address, lifetime: c.Verification.Lifetime})
	if err != nil {
		return spec, 0, original, err
	}
	if c.Verification.Policy.Authorize(grant, spec, c.Coordinator.QueryPolicy.Clock.Now()) != nil {
		return spec, 0, original, identity.ForbiddenError{}
	}
	return spec, version, flow, nil
}
