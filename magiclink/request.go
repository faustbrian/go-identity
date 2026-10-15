package magiclink

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/session"
)

// RequestRequest retains the exact raw email, callback, original request key and
// server-issued browser flow. Tenant, Caller, Origin, Network and Device require
// trusted transport provenance. Native composition owns canonical selection,
// current policy, risk, issuance and encrypted delivery. No user, signing key,
// expiry, delivery template or capability can be selected by the caller.
// Keep borrowed inputs immutable during calls; do not log field projections.
type RequestRequest struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Email                   email.AddressInput
	Intent                  Intent
	Callback                string
	IdempotencyKey          identity.IdempotencyKey
	PreAuthID               identity.PreAuthTransactionID
	Cookie                  auth.BearerCredential
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// Validate checks bounds and exact transport scope only. It never normalizes an
// address, authenticates a cookie, selects a recipient or creates state. A valid
// flow ID does not prove issued/current browser custody. Zero values deny.
func (r RequestRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "magiclink_request"} }
	if !boundedText(string(r.TenantID), 128) || string(r.Caller.Request.Tenant) != string(r.TenantID) || r.Caller.Request.Action != "identity.magic-link.request" || r.Caller.PolicyRevision == 0 || !boundedText(string(r.Caller.Request.Subject.ID), 128) || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.Intent != SignInOnly && r.Intent != SignupIfAllowed || len(r.Email) == 0 || len(r.Email) > 4096 || !utf8.ValidString(string(r.Email)) || !httpsURL(r.Callback) || !httpsURL(r.Origin) || len(r.Network) == 0 || len(r.Network) > 255 || net.ParseIP(r.Network) == nil || r.Device != "" && !boundedText(r.Device, 255) {
		return bad()
	}
	switch r.Caller.Request.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return bad()
	}
	u, _ := url.Parse(r.Origin)
	if u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return bad()
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.PreAuthID)); err != nil {
		return bad()
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return bad()
	}
	return nil
}

// Format hides mailbox, callback, idempotency and original browser custody.
func (RequestRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.RequestRequest(redacted)"))
}

// MarshalJSON prevents implicit export of sensitive workflow input.
func (RequestRequest) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// MarshalText prevents implicit textual export of sensitive workflow input.
func (RequestRequest) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// LogValue hides request fields from structured diagnostics.
func (RequestRequest) LogValue() slog.Value {
	return slog.StringValue("magiclink.RequestRequest(redacted)")
}

// RequestResult is an enumeration-safe original-command acknowledgement.
// Accepted means known commitment of request processing, identically for
// eligible and suppressed recipients. It never means a message was queued,
// delivered, a link usable, or a subject authenticated. Unknown/busy outcomes
// preserve the original attempt and must not cause issuance under a new key.
type RequestResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	Accepted  bool
}

// Validate checks coupled result shape, not evidence of durable commitment.
func (r RequestResult) Validate() error {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return identity.InvalidInputError{Field: "magiclink_result"}
	}
	switch r.Outcome {
	case identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
	default:
		return identity.InvalidInputError{Field: "magiclink_result"}
	}
	if r.Accepted != (r.Outcome == identity.CommitOutcomeCommitted) {
		return identity.InvalidInputError{Field: "magiclink_result"}
	}
	return nil
}

// RequestService is the native request/recovery workflow boundary, not a
// consumer-written store or delivery callback. Implementations preserve exact
// original issuance and encrypted message custody across retries/ambiguity;
// recovery never generates or sends another message. Dependencies remain owned
// by their existing packages. All calls are bounded and concurrency-safe under
// borrowed owner contracts. This port alone is not a delivered login service.
type RequestService interface {
	Request(context.Context, RequestRequest) (RequestResult, error)
	RecoverRequest(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (RequestResult, error)
}
