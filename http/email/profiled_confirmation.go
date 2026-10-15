package emailhttp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// ProfiledConfirmationService owns authenticated original-profile dispatch.
// It must select exactly one signup/managed-add owner from authenticated signed
// issuance provenance, not unsigned payload inspection or failed-source fallback.
// Native confirmation independently retains current policy and atomic use.
type ProfiledConfirmationService interface {
	VerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
	VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
}

// ProfiledConfirmationConfig selects one shared confirmation route, not two
// competing routes. It uses the same bounded no-session wire and trusted startup
// origin/actor/revision/rate policy as ConfirmationConfig. Service authenticates
// the complete original profile; borrowed owners must outlive concurrent calls.
type ProfiledConfirmationConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ProfiledConfirmationService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed authority and rate custody.
func (ProfiledConfirmationConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "emailhttp.ProfiledConfirmationConfig(redacted)")
}

// LogValue emits a constant marker.
func (ProfiledConfirmationConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.ProfiledConfirmationConfig(redacted)")
}

// MarshalJSON rejects implicit deployment export.
func (ProfiledConfirmationConfig) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText rejects implicit deployment export.
func (ProfiledConfirmationConfig) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
