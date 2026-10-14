package reference

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// OtpVerificationRateSource authenticates original issuance and exact retained
// code/browser intent before returning the immutable subject, child and signed
// lifetime for HTTP quotas. Matching historical results precede mutable factor
// and continuation reads, including counted denial and consumed-child success.
// Changed historical intent fails closed. New requests require current native
// primary/factor/recipient/browser admission, without code comparison, attempt
// debit, reservation, session issuance or freshness renewal. This metadata grants
// no completion authority. Expired proofs use code-free RecoverOtpVerify.
// All errors, panics and cancellation return zero metadata; calls are bounded
// by the configured duration and earlier inbound deadline.
func (s *PasswordOTPLoginCompletionService) OtpVerificationRateSource(ctx context.Context, r mfa.OtpVerifyRequest) (user identity.UserID, child string, lifetime time.Duration, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, child, lifetime = "", "", 0
		}
	}()
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return "", "", 0, invalidPasswordOTPCompletion()
	}
	state := s.state()
	if state == nil || state.sender == nil {
		return "", "", 0, invalidPasswordOTPCompletion()
	}
	config := state.sender.config
	if r.Enrollment != nil || r.TrustDevice || !slices.Contains(config.AllowedOrigins, r.Origin) || r.Caller.PolicyRevision != authorization.Revision(config.Coordinator.AdmissionPolicy.PolicyVersion) {
		return "", "", 0, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, config.MaximumDuration)
	defer stop()
	defer func() {
		if bounded.Err() != nil {
			err = bounded.Err()
		}
	}()
	grant, _, _, err := state.sender.issuer.ReadIssuanceOrigin(bounded, state.sender.pool, r.Proof, "identity.mfa.complete")
	if err != nil {
		return "", "", 0, err
	}
	payload := grant.Payload()
	lifetime = payload.ExpiresAt.Sub(payload.IssuedAt)
	if payload.Tenant != string(r.TenantID) || payload.ID != string(r.ContinuationID) || payload.Issuer != config.IssuerURL || lifetime < time.Second || lifetime > 5*time.Minute || lifetime%time.Microsecond != 0 {
		return "", "", 0, identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(payload.Subject); err != nil {
		return "", "", 0, identity.ForbiddenError{}
	}
	p := &passwordOTPCompletionPhase{state: state, request: r}
	if err := p.compose(); err != nil {
		return "", "", 0, err
	}
	p.original, err = p.originalCommand()
	if err != nil {
		return "", "", 0, err
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(config.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.PreAuthID)}
	history, present, historyErr := p.coordinator.QueryMFAOTPCommand(bounded, p.original, caller)
	if present {
		if history.Validate() != nil {
			return "", "", 0, identity.UnavailableError{}
		}
		if historyErr != nil {
			var denied identity.ForbiddenError
			if history.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(historyErr, &denied) {
				return "", "", 0, historyErr
			}
		}
		return identity.UserID(payload.Subject), payload.ID, lifetime, nil
	}
	if historyErr != nil {
		return "", "", 0, historyErr
	}
	source, err := state.sender.readCompletionSource(bounded, r)
	if err != nil {
		return "", "", 0, err
	}
	defer source.destroy()
	scope, err := source.continuation.Bindings()
	if err != nil || string(scope.SubjectID) != payload.Subject || string(scope.ID) != payload.ID || !scope.IssuedAt.Equal(payload.IssuedAt) || !scope.ExpiresAt.Equal(payload.ExpiresAt) {
		return "", "", 0, identity.ForbiddenError{}
	}
	return identity.UserID(payload.Subject), payload.ID, lifetime, nil
}
