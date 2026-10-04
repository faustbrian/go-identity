package delivery

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// StatusScope supplies an authenticated caller and exact target user to the
// owned adapter. IDs and prior decisions confer no authority: policy is checked
// for each observation. Callers must not mutate attributes during the call.
type StatusScope struct {
	UserID     identity.UserID
	ActorScope authorization.DecisionContext
}

// MutationScope freezes the original command and primary status-version fence
// before first submission. Retries must retain these fields unchanged; do not
// reread status to rewrite a pending command. ActorScope is trusted composition
// input, not transport authentication or permission to bypass current policy.
type MutationScope struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	ExpectedStatusVersion uint64
}

// ReconcileScope additionally freezes the durable lookup step. Zero begins the
// sequence; the opaque checkpoint and next step must come from the prior owned
// result. A checkpoint never permits resubmitting a delivery.
type ReconcileScope struct {
	MutationScope
	ExpectedStep uint64
}

// SignedReceiptCallback carries untrusted Golib-profile evidence, not a vendor
// signature approximation. Routing fields, canonical UTC SignedAt and exact Body
// bytes are signed. Signature is the 32-byte v1 HMAC, not hex. The owned adapter
// bounds and authenticates the envelope before accepting normalized receipt data.
// The caller must bound transport reads and retain bytes unchanged during calls.
type SignedReceiptCallback struct {
	TenantID              TenantID
	Provider              string
	ProviderConfigVersion uint64
	KeyID                 string
	SignedAt              time.Time
	Body                  []byte
	Signature             [32]byte
}

func (EnqueueScope) Format(s fmt.State, _ rune)            { redact(s) }
func (StatusScope) Format(s fmt.State, _ rune)             { redact(s) }
func (MutationScope) Format(s fmt.State, _ rune)           { redact(s) }
func (ReconcileScope) Format(s fmt.State, _ rune)          { redact(s) }
func (SignedReceiptCallback) Format(s fmt.State, _ rune)   { redact(s) }
func (EnqueueScope) LogValue() slog.Value                  { return slog.StringValue("delivery(redacted)") }
func (StatusScope) LogValue() slog.Value                   { return slog.StringValue("delivery(redacted)") }
func (MutationScope) LogValue() slog.Value                 { return slog.StringValue("delivery(redacted)") }
func (ReconcileScope) LogValue() slog.Value                { return slog.StringValue("delivery(redacted)") }
func (SignedReceiptCallback) LogValue() slog.Value         { return slog.StringValue("delivery(redacted)") }
func (EnqueueScope) MarshalJSON() ([]byte, error)          { return nil, ErrSerializationForbidden }
func (StatusScope) MarshalJSON() ([]byte, error)           { return nil, ErrSerializationForbidden }
func (MutationScope) MarshalJSON() ([]byte, error)         { return nil, ErrSerializationForbidden }
func (ReconcileScope) MarshalJSON() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (SignedReceiptCallback) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
