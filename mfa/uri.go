package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// TotpUriRequest names one pending enrollment and a separate canonical random
// reveal command. CommandID stays unchanged across retries and cannot equal
// EnrollmentID. Session/CSRFToken are borrowed original-session custody; neither
// selects an owner, grants factor authority or bypasses current admission.
// TenantID/Caller/Origin/Network require trusted transport provenance. Origin is
// an exact HTTPS origin, not a redirect or arbitrary URL. Native composition
// must compare the pending enrollment's original source session, enforce its
// retained synchronizer and origin policy, and atomically consume the reveal.
type TotpUriRequest struct {
	TenantID     identity.TenantID
	EnrollmentID EnrollmentID
	CommandID    identity.CommandID
	Session      auth.BearerCredential
	CSRFToken    session.CSRFToken
	Caller       authorization.DecisionContext
	Origin       string
	Network      string
}

// Validate checks intrinsic input and trusted-scope consistency only. It owns
// no IO, clock, transaction or authority. The opaque synchronizer's bounded
// zero value is rejected without consuming its reveal permission. Cryptographic token
// matching, original-session possession, current owners, expiry, risk and
// reveal-once consumption remain mandatory native checks after validation.
func (r TotpUriRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_totp_uri"} }
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.EnrollmentID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil || r.CommandID == identity.CommandID(r.EnrollmentID) {
		return bad()
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return bad()
	}
	if r.CSRFToken == (session.CSRFToken{}) {
		return bad()
	}
	request := r.Caller.Request
	if r.Caller.Validate() != nil || r.Caller.PolicyRevision == 0 || request.Tenant != authorization.TenantID(r.TenantID) || request.Subject.Kind != authorization.SubjectUser || request.Action != "identity.mfa.totp-uri" || request.Resource.Type != "identity.user" || request.Resource.ID != authorization.ResourceID(request.Subject.ID) {
		return bad()
	}
	if _, err := identity.ParseIdentifierID(string(request.Subject.ID)); err != nil {
		return bad()
	}
	if !totpCompletionURL(r.Origin, true) || len(r.Network) > 255 || net.ParseIP(r.Network) == nil {
		return bad()
	}
	return nil
}

// TotpUriResult separates historical durable outcome from ephemeral URI
// disclosure. Only an error-free first committed reveal carries URI. Conflict,
// replay, in-progress, unknown, cancellation, recovery and transport failure
// carry none and never mint a successor reveal. Outcome zero means no
// authoritative observation, not proof of rollback. Do not log this result or
// serialize it implicitly; the selected transport explicitly transfers URI and
// sends Cache-Control:no-store and Pragma:no-cache on every response.
type TotpUriResult struct {
	Outcome identity.CommitOutcome
	URI     RevealOnceURI
}

// TOTPURIService is the narrow reveal-once workflow port. Select the native
// platform implementation, not a consumer-written factor store or handler.
// Calls are bounded and concurrent-safe with immutable request custody; only
// one caller can consume disclosure. Recovery accepts no bearer/CSRF/secret and
// independently enforces current result-access policy, returning no URI.
type TOTPURIService interface {
	TotpUri(context.Context, TotpUriRequest) (TotpUriResult, error)
	RecoverTotpUri(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (TotpUriResult, error)
}

// Format redacts borrowed session/synchronizer and transport custody.
func (TotpUriRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TotpUriRequest(redacted)"))
}

// MarshalJSON denies implicit borrowed-credential export.
func (TotpUriRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit text/map-key credential export.
func (TotpUriRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (TotpUriRequest) LogValue() slog.Value { return slog.StringValue("mfa.TotpUriRequest(redacted)") }

// Format redacts provisioning URI and correlated outcome metadata.
func (TotpUriResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TotpUriResult(redacted)"))
}

// MarshalJSON denies implicit secret-delivery export.
func (TotpUriResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit text/map-key secret export.
func (TotpUriResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (TotpUriResult) LogValue() slog.Value { return slog.StringValue("mfa.TotpUriResult(redacted)") }
