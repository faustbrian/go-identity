package emailhttp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// ChangeConfirmationService is the native primary-change port. Its original
// source read binds the change intent; completion owns new-address proof,
// atomic primary selection, old notification and required session effects.
// Methods honor bounded cancellation and concurrent independent requests.
type ChangeConfirmationService interface {
	ChangeConfirmationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
	ChangeConfirm(context.Context, email.ChangeConfirmRequest) (email.ChangeConfirmResult, error)
}

// ChangeConfirmationConfig selects new-address possession confirmation, not
// verification-only, signup or automatic signin. Network/origin/actor/revision
// are trusted startup values. Service, Rate and prompt Now remain borrowed and
// must outlive handlers; drain requests before closing them. MaximumDuration is
// 1ms..30s and earlier cancellation wins. Construction performs no IO.
type ChangeConfirmationConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ChangeConfirmationService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// NewChangeConfirmationHandler selects POST /v1/email/change-confirm with the
// same closed body, pre-proof IP admission, original subject/grant budgets and
// no-session response custody as verification. Only ChangeConfirm executes;
// no proof, action, primary policy or recovery identity is reinterpreted.
func NewChangeConfirmationHandler(c ChangeConfirmationConfig) (http.Handler, error) {
	return NewChangeConfirmationHandlerWithMiddleware(c, nil)
}

// NewChangeConfirmationHandlerWithMiddleware binds hooks to the actual typed
// protected phases. Hooks cannot replace proof custody or select another owner.
func NewChangeConfirmationHandlerWithMiddleware(c ChangeConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilService(c.Service) {
		return nil, identityhttp.ErrInvalidInput
	}
	transport := ConfirmationConfig{Network: c.Network, Rate: c.Rate, Origin: c.Origin, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
	execute := func(ctx context.Context, request email.VerificationConfirmRequest) (confirmationExecutionResult, error) {
		out, err := c.Service.ChangeConfirm(ctx, email.ChangeConfirmRequest(request))
		q, bindingErr := out.Recovery.Bindings()
		return confirmationExecutionResult{Outcome: out.Outcome, Address: out.Address, Recovery: q, Replayed: out.Replayed, RetryAfter: out.RetryAfter, valid: out.Validate() == nil && bindingErr == nil}, err
	}
	return newConfirmationOperation(transport, m, execute, c.Service.ChangeConfirmationRateSource, "identity.email.change-confirm")
}

// NewChangeConfirmationFeature selects only the canonical change-confirm
// operation and concrete wire contract. Omission exposes neither route nor
// metadata; select a single email feature when composing multiple operations.
func NewChangeConfirmationFeature(c ChangeConfirmationConfig) (identityhttp.Feature, error) {
	return NewChangeConfirmationFeatureWithMiddleware(c, nil)
}

// NewChangeConfirmationFeatureWithMiddleware selects the actual protected
// pipeline rather than a placeholder handler.
func NewChangeConfirmationFeatureWithMiddleware(c ChangeConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{ChangeConfirmation: &c}, m)
}

// Format redacts runtime composition.
func (ChangeConfirmationConfig) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "emailhttp.ChangeConfirmationConfig(redacted)")
}

// LogValue emits a constant marker.
func (ChangeConfirmationConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.ChangeConfirmationConfig(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (ChangeConfirmationConfig) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit text export.
func (ChangeConfirmationConfig) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
