package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ChallengeID names one exact original MFA challenge, not possession or a
// session. This browser TOTP-completion profile uses the continuation's
// canonical random128 identity; enrollment/step-up are distinct future profiles.
type ChallengeID string

// FactorID selects an enrolled factor under the proof-authenticated account.
// It cannot select a user, factor generation, enrollment version or method.
// The initial durable TOTP profile uses canonical random128 identities.
type FactorID string

// TotpVerifyRequest submits original child proof, opaque code and browser cookie
// custody for login completion. No user, Remember, expiry or authority override
// is accepted. Trusted transport supplies Caller/TenantID/Origin/Network/Device;
// the native composition must authenticate the original child and consumed
// primary browser flow, enforce current policy/risk and execute atomically.
// ChallengeID must match the signed child; FactorID must belong to its account.
// TrustDevice is an explicit policy request; false issues none. Unsupported
// trusted-device policy must deny true, never silently ignore it. Borrowed
// secrets remain immutable until bounded execution ends; never serialize them.
type TotpVerifyRequest struct {
	TenantID                          identity.TenantID
	CommandID                         identity.CommandID
	ChallengeID                       ChallengeID
	FactorID                          FactorID
	Proof                             capability.Proof
	Code                              auth.OneTimeCode
	TrustDevice                       bool
	PreAuthID                         identity.PreAuthTransactionID
	Cookie                            auth.BearerCredential
	Caller                            authorization.DecisionContext
	Origin, Callback, Network, Device string
	// Enrollment selects pending-factor confirmation instead of login-child
	// completion. Nil preserves the existing login contract. Inactive login
	// fields must be absent; the original enable provenance is restored by the
	// native owner, not supplied as another caller-generated primary proof.
	Enrollment *TOTPEnrollmentConfirmation
}

// TOTPEnrollmentConfirmation borrows the original authenticated session and
// synchronizer for code-confirmed activation of FactorID. It is a distinct
// variant of identity.mfa.totp-verify, not a login continuation or step-up grant.
// Original enrollment evidence, current authority and atomic factor/recovery/
// session effects remain mandatory native-owner checks. Never mutate borrowed
// fields while a verification call is running.
type TOTPEnrollmentConfirmation struct {
	Session   auth.BearerCredential
	CSRFToken session.CSRFToken
}

// Validate checks bounded structure only; it performs no IO, proof transfer,
// factor computation, consumption or normalization. Opaque code construction
// supplies primitive 4..128-symbol bounds; the enrolled TOTP profile separately
// requires 6..10 digits. A malformed/mismatching factor submission must follow
// native shared-attempt policy, not bypass it through a structural success.
func (r TotpVerifyRequest) Validate() error {
	if r.Enrollment != nil {
		return r.validateEnrollmentConfirmation()
	}
	bad := func() error { return identity.InvalidInputError{Field: "mfa_totp_verify"} }
	if !validContinuationBrowserInput(continuationBrowserInput{tenant: r.TenantID, command: r.CommandID, continuation: ContinuationID(r.ChallengeID), flow: r.PreAuthID, proof: r.Proof, cookie: r.Cookie, caller: r.Caller, origin: r.Origin, callback: r.Callback, network: r.Network, device: r.Device}, "identity.mfa.totp-verify") {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.FactorID)); err != nil {
		return bad()
	}
	// Match identity's opaque command validation boundary. This discarded
	// public-key digest is never persisted or used to verify a submitted code.
	digest, err := r.Code.CommandDigest([32]byte{1}, "mfa.input.validation")
	clear(digest[:])
	if err != nil {
		return bad()
	}
	return nil
}

func totpCompletionURL(value string, origin bool) bool {
	// url.Parse loses an empty trailing fragment, which is still forbidden
	// at this exact browser-binding boundary. Escaped %23 remains ordinary data.
	if len(value) == 0 || len(value) > 2048 || strings.Contains(value, "#") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	return !origin || (u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery)
}

// TotpVerifyResult separates durable outcome from ephemeral credential delivery.
// Only a new error-free reconciled commit may carry token/CSRF custody. Replay,
// unknown outcomes, recovery, cancellation and delivery failure return neither.
// Session metadata is historical, not current access authority. This selected
// login variant returns no enrollment activation. Enrollment confirmation
// returns no login credential or reusable step-up proof.
type TotpVerifyResult struct {
	Outcome   identity.CommitOutcome
	Session   session.IssueResult
	CSRFToken session.CSRFToken
	// Enrollment is historical activation metadata for the explicit enrollment
	// variant only. It grants no session or current factor authority. Its expiry
	// is the original pending deadline, not an active-factor expiration reset.
	Enrollment Enrollment
}

func (r TotpVerifyRequest) validateEnrollmentConfirmation() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_totp_verify"} }
	if r.ChallengeID != "" || r.PreAuthID != "" || r.Proof != (capability.Proof{}) || r.Cookie.Token() != "" || r.Callback != "" || r.Device != "" {
		return bad()
	}
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.FactorID)); err != nil || r.CommandID == identity.CommandID(r.FactorID) {
		return bad()
	}
	if _, err := session.ParseToken(r.Enrollment.Session.Token()); err != nil {
		return bad()
	}
	if r.Enrollment.CSRFToken == (session.CSRFToken{}) {
		return bad()
	}
	digest, err := r.Code.CommandDigest([32]byte{1}, "mfa.input.validation")
	clear(digest[:])
	if err != nil {
		return bad()
	}
	request := r.Caller.Request
	if r.Caller.Validate() != nil || r.Caller.PolicyRevision == 0 || request.Tenant != authorization.TenantID(r.TenantID) || request.Subject.Kind != authorization.SubjectUser || request.Action != "identity.mfa.totp-verify" || request.Resource.Type != "identity.user" || request.Resource.ID != authorization.ResourceID(request.Subject.ID) {
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

// Format prevents traversal of borrowed enrollment session/synchronizer custody.
func (TOTPEnrollmentConfirmation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TOTPEnrollmentConfirmation(redacted)"))
}

// MarshalJSON denies implicit borrowed credential export.
func (TOTPEnrollmentConfirmation) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText denies implicit borrowed credential export.
func (TOTPEnrollmentConfirmation) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// TOTPCompletionService is the narrow typed TOTP-completion portion of the MFA
// service. Selected factories must reject unsupported variants before work.
// Core computation/policy remains in mfa; concrete composition selects
// real owned stores and the session issuer. Consumers supply configuration, not
// missing domain handlers. Recovery is code/proof-free and cannot redeliver a
// credential or restart the original primary authentication.
type TOTPCompletionService interface {
	TotpVerify(context.Context, TotpVerifyRequest) (TotpVerifyResult, error)
	RecoverTotpVerify(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (TotpVerifyResult, error)
}

// Format redacts factor, browser and transport custody for every verb.
func (TotpVerifyRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TotpVerifyRequest(redacted)"))
}

// MarshalJSON rejects implicit credential/request disclosure.
func (TotpVerifyRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text/map-key disclosure.
func (TotpVerifyRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts factor and original browser custody.
func (TotpVerifyRequest) LogValue() slog.Value {
	return slog.StringValue("mfa.TotpVerifyRequest(redacted)")
}

// Format redacts ephemeral delivery and correlated result metadata.
func (TotpVerifyResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TotpVerifyResult(redacted)"))
}

// MarshalJSON rejects implicit reveal-once result export.
func (TotpVerifyResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text/map-key disclosure.
func (TotpVerifyResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts result and credential custody.
func (TotpVerifyResult) LogValue() slog.Value {
	return slog.StringValue("mfa.TotpVerifyResult(redacted)")
}
