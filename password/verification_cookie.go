package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// CookieVerificationRequest explicitly carries original cookie-session custody
// in Request.Session's existing opaque bearer container and the session owner's
// synchronizer. This does not select the bearer-only verification profile.
// Trusted HTTP separately enforces exact origin and exclusive cookie/CSRF
// channels. Borrowed password and token remain immutable and caller-owned.
// Neither token possession nor structural validation grants proof authority.
type CookieVerificationRequest struct {
	Request   VerificationRequest
	CSRFToken session.CSRFToken
}

// Validate checks nested intrinsic scope/live-password bounds and rejects zero
// synchronizer custody without revealing, digesting or checking it. The native
// cookie owner must validate the exact named token/key and complete active
// primary session under the proof-issuance transaction, including after races.
// Success creates no CSRF, session, freshness, signing or issuance authority.
func (r CookieVerificationRequest) Validate() error {
	if r.CSRFToken == (session.CSRFToken{}) {
		return ErrPasswordWork
	}
	return r.Request.Validate()
}

// Format redacts original cookie, synchronizer, password and provenance.
func (CookieVerificationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.CookieVerificationRequest(redacted)")
}

// MarshalJSON denies implicit sensitive request export.
func (CookieVerificationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText denies text and map-key export of original custody.
func (CookieVerificationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// LogValue returns a fixed redacted marker.
func (CookieVerificationRequest) LogValue() slog.Value {
	return slog.StringValue("password.CookieVerificationRequest(redacted)")
}

// CookieVerificationService is the distinct adapter-neutral native browser port.
// Select the platform's explicit cookie owner, never a tokenless bearer adapter
// or consumer-written proof builder. Verify checks the original synchronizer
// against its exact eligible named key and fences the complete active primary
// session/family with password/current-authority/risk/proof/audit/outbox work.
// It issues only the authentication owner's original bounded proof after fresh
// known commit; it never creates, extends, rotates or consumes a session or CSRF
// token. Valid concurrent non-keyed invocations may issue distinct proofs.
// Failed or ambiguous delivery preserves original command/outcome observations
// without proof or automatic retries. Recover requires current original scoped
// disclosure policy and returns history without password, token or proof; it
// never reissues authority or renews original evidence. Cancellation, borrowed
// ownership, concurrent dependencies and context bounds follow VerificationService.
type CookieVerificationService interface {
	Verify(context.Context, CookieVerificationRequest) (VerificationResult, error)
	Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (VerificationResult, error)
}
