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
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// ManagedConfirmationService is the consumer-owned management-link port.
// password/postgres.EmailManagementService implements it without HTTP imports.
// The source authenticates original management provenance, not signup intent;
// confirmation rechecks current authority and atomically consumes the proof.
// Historical rate metadata is not a validity lease. Implementations honor
// bounded contexts, concurrent independent calls and secret-safe diagnostics.
type ManagedConfirmationService interface {
	ManagedVerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
	VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
}

// ManagedConfirmationConfig explicitly selects pending managed-address
// verification, not signup, primary change, session issuance or automatic signin.
// Trusted network/origin/actor/revision and rate identity are startup policy,
// never browser claims. Service, limiter and prompt concurrency-safe Now remain
// borrowed and must outlive handlers; drain before closing them. MaximumDuration
// is 1ms..30s with earlier cancellation preserved. Construction performs no IO
// or registration. Collections must remain immutable during construction.
type ManagedConfirmationConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ManagedConfirmationService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts deployment composition.
func (ManagedConfirmationConfig) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "emailhttp.ManagedConfirmationConfig(redacted)")
}

// LogValue emits a constant marker.
func (ManagedConfirmationConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.ManagedConfirmationConfig(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (ManagedConfirmationConfig) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit deployment export.
func (ManagedConfirmationConfig) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// NewManagedConfirmationHandler selects the existing closed HTTPS wire and
// real management owner. It preserves original grant-bound rate ordering,
// no-store/no-session response custody and exact-command outcomes. It registers
// no routes; omission exposes nothing. No signup-source fallback is performed.
func NewManagedConfirmationHandler(c ManagedConfirmationConfig) (http.Handler, error) {
	return NewManagedConfirmationHandlerWithMiddleware(c, nil)
}

// NewManagedConfirmationHandlerWithMiddleware binds the same actual typed
// phases as signup confirmation without substituting its provenance owner.
func NewManagedConfirmationHandlerWithMiddleware(c ManagedConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilService(c.Service) {
		return nil, identityhttp.ErrInvalidInput
	}
	transport := ConfirmationConfig{Network: c.Network, Rate: c.Rate, Origin: c.Origin, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
	return newConfirmationHandler(transport, m, c.Service, c.Service.ManagedVerificationRateSource)
}

// NewManagedConfirmationFeature contributes the selected management handler
// and concrete confirmation wire schema to the opt-in HTTP graph. Select one
// owner per canonical route; duplicate signup/management selection is rejected
// by composition rather than silently choosing an owner.
func NewManagedConfirmationFeature(c ManagedConfirmationConfig) (identityhttp.Feature, error) {
	return NewManagedConfirmationFeatureWithMiddleware(c, nil)
}

// NewManagedConfirmationFeatureWithMiddleware contributes actual protected
// execution with hooks that cannot replace proof custody or reenter a phase.
func NewManagedConfirmationFeatureWithMiddleware(c ManagedConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{ManagedConfirmation: &c}, m)
}
