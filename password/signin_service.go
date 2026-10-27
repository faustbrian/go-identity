package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SigninService is the adapter-neutral native password-login port. Each Signin
// creates one server-owned non-keyed attempt; never resubmit after ambiguity.
// The native adapter owns canonical discovery, dummy verification, current
// status/verification/risk/factor admission, and atomic hash upgrade, original
// pre-auth consumption, signed authentication, session, audit and outbox work.
// A single-factor implementation must deny when further factors are required,
// never substitute a password proof for an actual MFA-owned continuation.
// All IO honors ctx and bounded service deadlines; no automatic retry is allowed.
// Error/cancellation/unknown/recovery/replay returns no bearer or synchronizer,
// even when original known committed history is retained in the result.
// Concurrent calls cannot issue multiple sessions from the same original flow.
type SigninService interface {
	Signin(context.Context, SigninRequest) (SigninResult, error)
	RecoverSignin(context.Context, SigninRecoveryRequest) (SigninResult, error)
}

// SigninRecovery is immutable password-free original attempt correlation, not
// permission to disclose history or resume login. It retains the original user
// OR anonymous-flow namespace, independently of the eventual session user.
// Zero is invalid; copies are safe for concurrent reads and own no resources.
type SigninRecovery struct {
	query identity.RecoveryQuery
	flow  identity.PreAuthTransactionID
}

// NewSigninRecovery reconstructs bounded scalar correlation for recovery only.
// Native Signin alone allocates attempts. The selector uses the existing kernel
// query, exact password-signin operation and record-omitted profile. Anonymous
// scope must be the original pre-auth ID; never retarget it to a resolved user.
// This performs no IO, possession check or authority validation.
func NewSigninRecovery(q identity.RecoveryQuery, flow identity.PreAuthTransactionID) (SigninRecovery, error) {
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return SigninRecovery{}, ErrPasswordWork
	}
	if _, err := identity.ParsePreAuthTransactionID(string(flow)); err != nil {
		return SigninRecovery{}, ErrPasswordWork
	}
	if !boundedChangeText(string(q.TenantID)) || !boundedChangeText(string(q.ActorID)) || (q.OperationID != "identity.password.signin" && q.OperationID != "identity.username.signin" && q.OperationID != "identity.phone.password-signin") || q.RecordID != "" || q.LinkMode != 0 || (q.UserID == "") == (q.AnonymousFlowID == "") {
		return SigninRecovery{}, ErrPasswordWork
	}
	if q.UserID != "" && !boundedChangeText(string(q.UserID)) || q.AnonymousFlowID != "" && q.AnonymousFlowID != string(flow) {
		return SigninRecovery{}, ErrPasswordWork
	}
	switch q.ActorKind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return SigninRecovery{}, ErrPasswordWork
	}
	return SigninRecovery{query: q, flow: flow}, nil
}

// Bindings returns scalar copies for a trusted explicit transport projection.
// Every field must match retained primary history and current disclosure policy;
// passing this structural check cannot authorize disclosure or reexecution.
func (r SigninRecovery) Bindings() (identity.RecoveryQuery, identity.PreAuthTransactionID, error) {
	if _, err := NewSigninRecovery(r.query, r.flow); err != nil {
		return identity.RecoveryQuery{}, "", err
	}
	return r.query, r.flow, nil
}

// SigninRecoveryRequest carries original cookie possession and fresh trusted
// caller provenance, never a password or the original secret-bearing command.
// The adapter checks retained original custody/current disclosure policy even
// after pre-auth consumption/expiry; an executable login flow is not required.
// It may reconcile the original frozen attempt, not rerun password comparison,
// charge another login attempt, issue credentials or renew authority freshness.
// Caller collections must remain immutable during the call.
type SigninRecoveryRequest struct {
	Recovery SigninRecovery
	Cookie   auth.BearerCredential
	Caller   authorization.DecisionContext
	Origin   string
	Network  string
	Device   string
}

// Validate checks bounded structure and exact original actor/tenant agreement.
// Actual cookie possession, original flow binding and current authorization
// remain native primary checks; no history is disclosed by this method.
func (r SigninRecoveryRequest) Validate() error {
	q, _, err := r.Recovery.Bindings()
	if err != nil || q.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || q.ActorKind != r.Caller.Request.Subject.Kind || r.Caller.Request.Action != authorization.Action(q.OperationID) || validateSigninProvenance(q.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil {
		return ErrPasswordWork
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// SigninTransport selects one closed original-session delivery contract.
// It does not authenticate credentials or select an HTTP handler.
type SigninTransport uint8

const (
	// CookieSignin is the existing default cookie and synchronizer profile.
	CookieSignin SigninTransport = iota
	// BearerSignin is an explicitly selected bearer-only profile. It forbids
	// cookie metadata, synchronizer delivery and stored session CSRF state.
	BearerSignin
)

// SigninResult preserves the sole session-owned issuance/outcome and native
// reveal-once custody. Authenticated means known committed session history,
// not current validity or permission to use it. SessionID survives authorized
// historical disclosure when live Session payload has been deleted; never
// fabricate a partial Session. Recovery retains the original command namespace.
// Rejected means no authenticated outcome is returned, not that credentials
// were wrong or that an Unknown command rolled back. Inspect CommitOutcome.
// ChallengeRequired describes committed partial authentication, never session
// authority. Its challenge cannot accompany a session, cookie or synchronizer.
// Fresh bearer exists only for original error-free uncancelled commit; the
// default CookieSignin additionally requires synchronizer delivery. Explicit
// BearerSignin omits all cookie metadata and CSRF state. Replay/recovery/errors
// must omit credentials and all cookie metadata. Cookie.Value
// is always empty; trusted HTTP alone reveals the original token into a cookie.
// Zero is an unobserved service error result, not a valid terminal observation.
type SigninResult struct {
	Transport SigninTransport
	State     auth.SignInState
	SessionID string
	Issuance  session.IssueResult
	CSRFToken session.CSRFToken
	Recovery  SigninRecovery
	Challenge MFAChallengeResult
}

// MFAChallengeResult retains the original password-first continuation metadata.
// Only the original successful commit may carry reveal-once Proof custody;
// recovery/replay omit it. ID and expiry do not authenticate a user. No session
// credential or synchronizer may accompany this result. Copies retain the same
// opaque capability custody and cannot renew its lifetime.
type MFAChallengeResult struct {
	ID        identity.CommandID
	Proof     capability.Proof
	Method    string
	ExpiresAt time.Time
}

// Format redacts the challenge credential and correlated metadata.
func (MFAChallengeResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.MFAChallengeResult(redacted)")
}

// MarshalJSON denies implicit credential export; trusted transport owns reveal.
func (MFAChallengeResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit textual credential export.
func (MFAChallengeResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (MFAChallengeResult) LogValue() slog.Value {
	return slog.StringValue("password.MFAChallengeResult(redacted)")
}

// Validate checks result shape/correlation without revealing or authenticating
// tokens, inspecting current authority, or creating delivery permission. The
// caller must separately withhold credentials on error/cancellation. A copied
// already-revealed opaque token remains structurally nonzero; only its native
// owner determines whether it can still be revealed.
func (r SigninResult) Validate() error {
	q, _, err := r.Recovery.Bindings()
	i := r.Issuance
	if err != nil || (r.Transport != CookieSignin && r.Transport != BearerSignin) || q.CommandID != i.CommandID || i.RetryAfter < 0 || i.RetryAfter > 0 && i.CommitOutcome != identity.CommitOutcomeInProgress || i.Cookie.Value != "" || i.Cookie.Raw != "" || len(i.Cookie.Unparsed) != 0 {
		return ErrPasswordWork
	}
	hasToken, hasCSRF := i.Token != (session.Token{}), r.CSRFToken != (session.CSRFToken{})
	if r.State == auth.SignInStateChallengeRequired {
		c := r.Challenge
		if _, err := identity.ParseCommandID(string(c.ID)); err != nil || r.Transport != CookieSignin || i.CommitOutcome != identity.CommitOutcomeCommitted || r.SessionID != "" || i.Session != (session.Session{}) || hasToken || hasCSRF || !emptySigninCookie(i.Cookie) || c.Method != "totp" || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(time.Unix(0, 0)) || c.ExpiresAt.Nanosecond() != 0 || i.Replayed && c.Proof != (capability.Proof{}) {
			return ErrPasswordWork
		}
		return nil
	}
	if r.Challenge != (MFAChallengeResult{}) {
		return ErrPasswordWork
	}
	if r.Transport == CookieSignin && hasToken != hasCSRF || r.Transport == BearerSignin && (hasCSRF || !emptySigninCookie(i.Cookie) || i.Session.CSRFState() != (session.CSRFState{})) || (i.Replayed || !hasToken) && !emptySigninCookie(i.Cookie) {
		return ErrPasswordWork
	}
	switch i.CommitOutcome {
	case identity.CommitOutcomeCommitted:
		if r.State != auth.SignInStateAuthenticated || !boundedChangeText(r.SessionID) || i.Replayed && hasToken {
			return ErrPasswordWork
		}
		if i.Session == (session.Session{}) {
			if !i.Replayed || hasToken {
				return ErrPasswordWork
			}
		} else {
			b, err := i.Session.Bindings()
			if err != nil || b.SessionID != r.SessionID || b.TenantID != q.TenantID || q.UserID != "" && b.UserID != q.UserID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" {
				return ErrPasswordWork
			}
		}
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
		if r.State != auth.SignInStateRejected || r.SessionID != "" || i.Session != (session.Session{}) || hasToken {
			return ErrPasswordWork
		}
	default:
		return ErrPasswordWork
	}
	return nil
}

func emptySigninCookie(c http.Cookie) bool {
	return c.Name == "" && c.Value == "" && c.Quoted == false && c.Path == "" && c.Domain == "" && c.Expires.IsZero() && c.RawExpires == "" && c.MaxAge == 0 && !c.Secure && !c.HttpOnly && c.SameSite == 0 && !c.Partitioned && c.Raw == "" && len(c.Unparsed) == 0
}

func (SigninRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SigninRecovery(redacted)")
}
func (SigninRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecovery) LogValue() slog.Value {
	return slog.StringValue("password.SigninRecovery(redacted)")
}
func (SigninRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SigninRecoveryRequest(redacted)")
}
func (SigninRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("password.SigninRecoveryRequest(redacted)")
}
func (SigninResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SigninResult(redacted)")
}
func (SigninResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninResult) LogValue() slog.Value         { return slog.StringValue("password.SigninResult(redacted)") }
