package email

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ChangeOrigin is sensitive original request provenance, not a credential or
// current authorization. Spec conserves the committed change's exact candidate,
// previous-address policy, session identity and exclusive validity. Session is
// the original password admission's immutable session, not today's successor.
// UserVersion and IdentifierAuthorityVersion are the predecessors of the single
// pending attachment performed by that request. FactorVersion is its genuine
// known-empty factor generation. A consumer must independently fence current
// authority and admit only the exact original request's attachment successor.
//
// OutputDigest is SHA-256 of the authenticated original encrypted preparation,
// not a digest of caller input or regenerated ciphertext. It commits original
// custody without exporting the password proof, bearer, link or encryption
// buffers. Reading provenance cannot renew its times or authorize replacement.
// Values own no resources, support concurrent reads, and must not be disclosed.
type ChangeOrigin struct {
	Spec                       ManagedVerificationSpec
	Session                    session.Session
	OutputDigest               [32]byte
	FactorVersion              uint64
	UserVersion                uint64
	IdentifierAuthorityVersion uint64
}

// ChangeOriginSource reads an actual committed self-user change request under
// current exact disclosure policy, independently of delivery or link possession.
// q names the original change command/candidate and one of
// identity.otp.email-change-request, identity.otp.email-change-confirm or
// identity.otp.email-change-confirm.recover. Recovery is a distinct current
// disclosure permission and never borrows confirmation authority.
// Generic attachments, verification-send/resend, foreign and noncommitted
// commands must deny. This is a trusted native workflow port, never a public
// inspection response or substitute for authenticating current session use.
//
// Implementations authenticate original encrypted custody, preserve original
// generations/times and return zero on error. They perform no preparation,
// issuance, comparison, consumption, delivery, mutation or authority renewal.
// Calls are cancellation-bounded and concurrent-safe; caller input is borrowed.
type ChangeOriginSource interface {
	ReadChangeOrigin(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ChangeOrigin, error)
}

// Format omits mailbox, source-session and original private correlation.
func (ChangeOrigin) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeOrigin(redacted)")
}

// LogValue prevents structured logging from disclosing original custody.
func (ChangeOrigin) LogValue() slog.Value { return slog.StringValue("email.ChangeOrigin(redacted)") }

// MarshalJSON rejects implicit original-intent export.
func (ChangeOrigin) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit original-intent and map-key export.
func (ChangeOrigin) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
