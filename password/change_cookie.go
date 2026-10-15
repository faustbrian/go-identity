package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// CookieChangeRequest adds the session owner's original synchronizer token to
// the unchanged keyed password-change request. Request contains the sole
// IdempotencyKey; no independent cookie retry key or proof is reconstructed.
// Trusted HTTP composition must reject mixed bearer/cookie channels and enforce
// exact permitted origin before invoking this port. CSRFToken alone proves
// neither origin, primary session activity nor permission to mutate.
// Treat the input as immutable during a call. Password remains caller-owned;
// neither validation nor this port transfers or destroys borrowed custody.
// Explicit fields are sensitive; never log them through unredacted wrappers.
type CookieChangeRequest struct {
	Request   ChangeRequest
	CSRFToken session.CSRFToken
}

// Validate checks only the nested request's intrinsic bounds and trusted scope.
// It deliberately does not reveal, digest or partially verify CSRFToken. Even
// zero token can pass this structural check: only the native cookie profile
// may admit exact primary synchronizer state, under the protected transaction's
// session fence. Success provides no CSRF, proof, freshness or mutation authority.
func (r CookieChangeRequest) Validate() error { return r.Request.Validate() }

// Format redacts the complete cookie request for every formatting verb.
func (CookieChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.CookieChangeRequest(redacted)")
}

// MarshalJSON rejects implicit export of credentials and borrowed input.
func (CookieChangeRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export of sensitive input.
func (CookieChangeRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed marker without token or request projections.
func (CookieChangeRequest) LogValue() slog.Value {
	return slog.StringValue("password.CookieChangeRequest(redacted)")
}

// CookieChangeService is the explicit adapter-neutral browser workflow port.
// It cannot be substituted for the tokenless ChangeService: implementations
// must deny absent, foreign or retired-key CSRF even on busy/terminal retries,
// retain the original command and non-renewable input evidence, and fence exact
// active primary session state with protected mutation. Retained key rotation
// must not create a second journal or alter the original intent/outcome.
// Change owns the same native proof/risk/password/session transaction as bearer
// change, not callback-ordered effects. Recover is scoped code-free original
// result access, not new mutation authority, and requires no resubmitted secret.
// Concurrency, bounded context, borrowed ownership and outcome/error semantics
// are otherwise those of ChangeService. Select a real platform-owned adapter.
type CookieChangeService interface {
	Change(context.Context, CookieChangeRequest) (ChangeResult, error)
	Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ChangeResult, error)
}
