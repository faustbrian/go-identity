package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Admission preserves original transport intent before any provider or hash
// work. It is not authorization or a primary-state check: the native phase
// must lock and consume this same record in its protected transaction.
func (*Repository) admitSignupFlow(r password.SignupRequest, flow session.PreAuthTransaction, key session.DigestKey, policy string, version uint64, now time.Time) error {
	s, err := flow.Bindings()
	if err != nil {
		return password.ErrPasswordWork
	}
	b, i := s.Binding, s.Binding.Intent
	actual, aerr := r.RememberPolicy.Bindings()
	original, oerr := i.Remember.Bindings()
	op := passwordSignupOperation()
	if r.Username != "" {
		op = usernameSignupOperation()
	}
	if b.ID != r.PreAuthID || i.TenantID != r.TenantID || i.Action != op.OperationID || r.Caller.Request.Action != authorization.Action(op.OperationID) || i.Origin != r.Origin || i.CallbackURL != r.CallbackURL || i.PolicyID != policy || i.PolicyVersion != version || aerr != nil || oerr != nil || actual != original {
		return password.ErrPasswordWork
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return password.ErrPasswordWork
	}
	digest, err := token.PreAuthDigest(key, b)
	if err != nil || flow.Check(now, b, digest) != nil {
		return password.ErrPasswordWork
	}
	return nil
}

// Verification-only and neutral signup consume the original flow without
// claiming a session. The existing session effect owns this transition when
// immediate issuance is selected; callers must never invoke both profiles.
// All mutation uses the active coordinator Work, so later risk/audit/delivery
// errors roll back the consumption with the account. No independent journal or
// transaction is created, and no caller-supplied reservation identity is used.
func (r *Repository) applySignupPreAuth(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, request password.SignupRequest, flow session.PreAuthTransaction, key session.DigestKey, storage sessionpg.Config) error {
	if ctx == nil || !r.configuredWriter() {
		return password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	b, err := signupFlowCommand(w, owner, c, request, false)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if r.admitSignupFlow(request, flow, key, b.PolicyID, b.PolicyVersion, now) != nil {
		return identity.ForbiddenError{}
	}
	bound, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || bound != b {
		return password.ErrPasswordWork
	}
	use := sessionpg.PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
	if err := sessionpg.ReservePreAuth(bounded, w, storage, flow, use); err != nil {
		return err
	}
	return sessionpg.FinalizePreAuth(bounded, w, storage, flow, use)
}

// The row remains locked by this Work, but time can advance during later audit
// or delivery phases. The native participant must invoke this from its final
// commit check rather than treating earlier consumption as a new timeline.
func (r *Repository) checkSignupPreAuthCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, request password.SignupRequest, flow session.PreAuthTransaction, key session.DigestKey) error {
	if ctx == nil || !r.configuredWriter() {
		return password.ErrPasswordWork
	}
	// Final scope is read-only. RequireFeatureCommand deliberately admits only
	// Apply, so the participant retains and compares its original command before
	// this call; FeatureScope separately proves its active final invocation.
	b, err := signupFlowCommand(w, owner, c, request, true)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if r.admitSignupFlow(request, flow, key, b.PolicyID, b.PolicyVersion, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func signupFlowCommand(w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, request password.SignupRequest, final bool) (identity.CommandBinding, error) {
	s, metadata := c.PasswordSignupFeature()
	_, cookie, custody := c.PasswordSignupCustody()
	b, f, transition, err := w.FeatureScope(owner)
	// Only the kernel's explicit neutral-acceptance branch changes the lifecycle
	// before final scope. It consumes the same flow without authenticating the
	// existing account or attaching any credential, delivery or session effect.
	validEvent := transition.EventType == "user.created.v1" || final && transition.EventType == "identity.password.signup.accepted.v1"
	if err != nil || !metadata || !custody || b != s.Binding || f.Operation != s.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || !signupOperation(s.Operation) || !validEvent || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || b.UserID != "" || b.AnonymousFlowID != string(request.PreAuthID) || b.TenantID != request.TenantID || b.ActorID != identity.ActorID(request.Caller.Request.Subject.ID) || b.ActorKind != request.Caller.Request.Subject.Kind || request.Caller.Request.Tenant != authorization.TenantID(b.TenantID) || request.Caller.Request.Action != authorization.Action(b.OperationID) || cookie.Token() != request.Cookie.Token() {
		return identity.CommandBinding{}, password.ErrPasswordWork
	}
	return b, nil
}
