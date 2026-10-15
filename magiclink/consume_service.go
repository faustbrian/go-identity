package magiclink

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ConsumeResult retains the original durable outcome separately from credential
// delivery. Session is historical metadata, not current authority. Only an exact
// new error-free commit can carry reveal-once bearer and CSRF custody; replay,
// recovery, unknown and cancellation must omit both. Cookie.Value stays empty.
// An explicitly selected native MFA profile may instead commit a challenge-only
// continuation. Missing or unsupported factor authority denies; the default
// profile still denies enrolled accounts rather than issuing a weaker session.
type ConsumeResult struct {
	Outcome   identity.CommitOutcome
	State     auth.SignInState
	Session   session.IssueResult
	CSRFToken session.CSRFToken
	Challenge MFAChallengeResult
}

// MFAChallengeResult is a challenge-only sign-in arm. Only the original new
// committed invocation may carry its reveal-once proof. ID/method/expiry are
// metadata, not authenticated session authority; no session or CSRF accompanies
// this arm. Retries and recovery omit the proof and never renew its lifetime.
type MFAChallengeResult struct {
	ID        identity.CommandID
	Proof     capability.Proof
	Method    string
	ExpiresAt time.Time
}

// Format redacts challenge credential and correlated metadata.
func (MFAChallengeResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.MFAChallengeResult(redacted)"))
}

// MarshalJSON rejects implicit credential export; trusted transport owns it.
func (MFAChallengeResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit textual credential export.
func (MFAChallengeResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts structured challenge diagnostics.
func (MFAChallengeResult) LogValue() slog.Value {
	return slog.StringValue("magiclink.MFAChallengeResult(redacted)")
}

// Format hides credentials and correlated historical metadata.
func (ConsumeResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.ConsumeResult(redacted)"))
}

// MarshalJSON denies implicit credential export; trusted HTTP owns delivery.
func (ConsumeResult) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// MarshalText denies implicit text and map-key export.
func (ConsumeResult) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// LogValue prevents credential and metadata disclosure in diagnostics.
func (ConsumeResult) LogValue() slog.Value {
	return slog.StringValue("magiclink.ConsumeResult(redacted)")
}

// ConsumptionService owns explicit consuming login and proof-free original
// outcome recovery. Implementations must compose real grant, primary recipient,
// browser, factor, risk and session owners atomically. Inspection is separate.
// Recovery never creates or redelivers a credential, even after a committed
// receipt. Calls borrow bounded context and immutable caller-owned custody.
type ConsumptionService interface {
	Consume(context.Context, ConsumeRequest) (ConsumeResult, error)
	RecoverConsume(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ConsumeResult, error)
}
