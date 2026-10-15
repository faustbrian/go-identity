package otp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Service owns OTP Send admission, original-request correlation, counted abuse
// assessment and atomic challenge/delivery issuance or equivalent suppression.
// Durable adapters provide construction; applications do not implement workflow
// stores or preparation choreography. Sending neither authenticates a user nor
// consumes a flow or creates a session. Calls must honor cancellation, support
// concurrency and preserve original command identity on retries and ambiguity.
type Service interface {
	Send(context.Context, SendRequest) (SendResult, error)
}

// SendFlow retains exactly one submitted possession variant and its selected
// original flow ID. It grants no authority: the service reads the original
// primary flow and authenticates possession independently. Zero is invalid.
// Copies are immutable, safe for concurrent reads, and must never be serialized.
type SendFlow struct {
	kind   FlowAuthorizationKind
	id     string
	bearer auth.BearerCredential
}

// NewPreAuthSendFlow retains the actual submitted cookie and original pre-auth
// ID. It performs no IO or authentication; invalid IDs/tokens deny.
func NewPreAuthSendFlow(id identity.PreAuthTransactionID, cookie auth.BearerCredential) (SendFlow, error) {
	if _, err := identity.ParsePreAuthTransactionID(string(id)); err != nil {
		return SendFlow{}, identity.InvalidInputError{Field: "otp.send.flow"}
	}
	return newSendFlow(FlowAuthorizationPreAuthTransaction, string(id), cookie)
}

// NewSessionSendFlow retains the actual submitted token and explicit original
// session ID (1..128 bounded text bytes). A token cannot select a different
// user's session. Construction does not authenticate or renew the session.
func NewSessionSendFlow(id string, token auth.BearerCredential) (SendFlow, error) {
	return newSendFlow(FlowAuthorizationAuthenticatedSession, id, token)
}

func newSendFlow(kind FlowAuthorizationKind, id string, bearer auth.BearerCredential) (SendFlow, error) {
	if !boundedText(id, 128, false) {
		return SendFlow{}, identity.InvalidInputError{Field: "otp.send.flow"}
	}
	for _, r := range id {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return SendFlow{}, identity.InvalidInputError{Field: "otp.send.flow"}
		}
	}
	if _, err := session.ParseToken(bearer.Token()); err != nil {
		return SendFlow{}, identity.InvalidInputError{Field: "otp.send.flow"}
	}
	return SendFlow{kind: kind, id: id, bearer: bearer}, nil
}

// Bindings returns submitted possession, not proof. Native adapters alone use
// it for primary-flow authentication. Never persist/log the returned bearer.
func (f SendFlow) Bindings() (FlowAuthorizationKind, string, auth.BearerCredential, error) {
	if f.kind != FlowAuthorizationPreAuthTransaction && f.kind != FlowAuthorizationAuthenticatedSession {
		return 0, "", auth.BearerCredential{}, identity.InvalidInputError{Field: "otp.send.flow"}
	}
	if _, err := newSendFlow(f.kind, f.id, f.bearer); err != nil {
		return 0, "", auth.BearerCredential{}, err
	}
	return f.kind, f.id, f.bearer, nil
}

// SendRequest is trusted direct-platform input, not HTTP JSON. Caller is the
// already authenticated composition context; its tenant/actor must match the
// selected flow's authority. No ID or attribute is authentication evidence.
// UserID is explicit and may be empty only for an anonymous pre-auth flow;
// recipient discovery must never retarget it. Destination is canonicalized by
// its owning email/phone workflow. Network is a canonical trusted client IP,
// not an untrusted forwarding header; Device is a trusted bounded identifier.
// TargetID binds the owning workflow's selected action/resource. IdempotencyKey
// comes from the caller and is replayed exactly; the service, never the caller,
// allocates its original CommandID. No input selects clearance or risk digest.
// Do not mutate Caller maps while calling Send. Request diagnostics redact all
// sensitive fields; explicit transport composition owns safe wire projections.
type SendRequest struct {
	TenantID       identity.TenantID
	UserID         identity.UserID
	Caller         authorization.DecisionContext
	Flow           SendFlow
	Channel        Channel
	Destination    DestinationInput
	Purpose        Purpose
	TargetID       string
	Network        string
	Device         string
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks bounded structure only, never caller/flow authority. Session
// requests require an explicit user; unknown purposes/variants and noncanonical
// network addresses fail closed. The native service owns stricter retained policy.
func (r SendRequest) Validate() error {
	bad := identity.InvalidInputError{Field: "otp.send"}
	if len(r.Caller.Request.Attributes) > 64 || len(r.Caller.Request.Subject.Groups) > 64 || len(r.Caller.Request.Subject.Attributes) > 64 || len(r.Caller.Request.Resource.Attributes) > 64 || len(r.Caller.Request.Environment.Attributes) > 64 {
		return bad
	}
	kind, _, _, err := r.Flow.Bindings()
	if err != nil || r.Caller.Validate() != nil || string(r.Caller.Request.Tenant) != string(r.TenantID) ||
		!boundedText(string(r.TenantID), 128, false) || !boundedText(string(r.Caller.Request.Subject.ID), 128, false) ||
		r.UserID != "" && !boundedText(string(r.UserID), 128, false) || kind == FlowAuthorizationAuthenticatedSession && r.UserID == "" ||
		!boundedText(r.TargetID, 256, false) || !boundedText(r.Device, 128, false) || !validPurpose(r.Purpose) ||
		(r.Channel != ChannelEmail && r.Channel != ChannelSMS) {
		return bad
	}
	if _, err := NewDestinationInput(r.Destination.Value()); err != nil {
		return bad
	}
	if r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return bad
	}
	address, err := netip.ParseAddr(r.Network)
	if err != nil || address.Zone() != "" || address.String() != r.Network {
		return bad
	}
	switch r.Caller.Request.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return bad
	}
	return nil
}

// SendResult is enumeration-safe command status. Committed means the request
// was accepted, not that a recipient exists, a challenge was issued or a message
// was delivered. Issuance and suppression expose the same fields. CommandID is
// the original server-owned identity; Unknown never implies success/failure.
// RetryAfter is populated only for InProgress. No credential/challenge/recipient
// identifier or message content is exposed. Adapters retain durable safe receipts.
type SendResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	RetryAfter time.Duration
}

func (SendFlow) Format(s fmt.State, _ rune)      { _, _ = s.Write([]byte("otp.SendFlow(redacted)")) }
func (SendFlow) MarshalJSON() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (SendFlow) MarshalText() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (SendFlow) LogValue() slog.Value            { return slog.StringValue("otp.SendFlow(redacted)") }
func (SendRequest) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("otp.SendRequest(redacted)")) }
func (SendRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SendRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SendRequest) LogValue() slog.Value         { return slog.StringValue("otp.SendRequest(redacted)") }
