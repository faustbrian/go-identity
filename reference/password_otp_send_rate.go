package reference

import (
	"context"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// OtpSendingRateSource returns only the native authenticated canonical recipient
// for internal HTTP delivery quotas. Exact retained-key custody precedes current
// primary/child/factor reads so an original send remains observable after login.
// Only authorized absence uses current source selection. No command allocation,
// code generation, comparison, counter debit, queue or session effect occurs.
// This sensitive tuple must never enter HTTP responses, logs or diagnostics and
// grants no sending authority. Native OtpSend independently owns its protected
// checks and effects. Errors/panics/cancellation return an empty destination.
func (s *PasswordOTPLoginSendService) OtpSendingRateSource(ctx context.Context, r mfa.OtpSendRequest) (destination string, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			destination = ""
		}
	}()
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return "", invalidPasswordOTPSend()
	}
	state := s.state()
	if state == nil || r.Enrollment != nil || !slices.Contains(state.config.AllowedOrigins, r.Origin) || r.Caller.PolicyRevision != authorization.Revision(state.config.Coordinator.AdmissionPolicy.PolicyVersion) {
		return "", identity.ForbiddenError{}
	}
	w, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if w.Err() != nil {
			err = w.Err()
		}
	}()
	p := &passwordOTPSendPhase{state: state, request: r}
	defer p.destroy()
	if err := p.compose(); err != nil {
		return "", err
	}
	intent, err := state.intent(r)
	if err != nil {
		return "", err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: passwordOTPSendOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(state.config.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	binding, wire, found, err := p.coordinator.ReadPreparedRequestKey(w, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: passwordOTPSendOperation()}, p)
	defer clear(wire)
	if err != nil {
		return "", err
	}
	if found {
		if err := p.restoreInput(w, binding, wire); err != nil {
			return "", err
		}
		return p.native.Recipient.Query.CanonicalValue, nil
	}
	source, err := state.readSendSource(w, r)
	if err != nil {
		return "", err
	}
	return source.recipient.Query.CanonicalValue, nil
}

// OtpSendingRateSource borrows the same native sender without new disclosure,
// correlation or freshness ownership.
func (s *PasswordOTPLoginCompletionService) OtpSendingRateSource(ctx context.Context, r mfa.OtpSendRequest) (string, error) {
	if s == nil || s.state == nil {
		return "", invalidPasswordOTPCompletion()
	}
	return s.state().config.Sender.OtpSendingRateSource(ctx, r)
}

func (f composedPasswordOTP) OtpSendingRateSource(ctx context.Context, r mfa.OtpSendRequest) (string, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", err
	}
	defer done()
	return f.state.features.passwordOTP.OtpSendingRateSource(w, r)
}
