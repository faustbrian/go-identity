package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SignupService is the adapter-neutral registration and original-recovery port.
// The adapter owns policy/attribute admission, canonical address interpretation,
// original pre-auth possession, risk/HIBP-before-hash and one keyed coordinated
// account/credential/verification/delivery commit. Identical retries select the
// original attempt; changed intent conflicts. Unknown is never inferred rollback.
// IO must honor ctx and bounded service deadlines. Concurrent calls must not
// duplicate accounts, proof issuance, delivery or sessions. The caller retains
// password custody and must destroy it after return.
//
// Required verification returns an enumeration-safe acknowledgement, no session
// or existing-account identity. Immediate session issuance requires explicit
// policy and actual satisfied verification/factor authority, never invented MFA.
// RecoverSignup checks original cookie possession/current disclosure authority;
// it never accepts a password, creates another attempt or redelivers credentials.
// Error, cancellation, replay and recovery withhold token, cookie and CSRF even
// when the authoritative result retains committed history. No UI is owned here.
type SignupService interface {
	Signup(context.Context, SignupRequest) (SignupResult, error)
	RecoverSignup(context.Context, SignupRecoveryRequest) (SignupResult, error)
}

// SignupRecovery is immutable password-free correlation, not execution or
// disclosure authority. The namespace always remains the original anonymous
// signup flow; a newly selected user must not replace it. Zero is invalid;
// copies are safe for concurrent reads and own no resources.
type SignupRecovery struct {
	query identity.RecoveryQuery
	flow  identity.PreAuthTransactionID
}

// NewSignupRecovery reconstructs bounded scalar correlation using the existing
// kernel query. Signup alone selects the original command. The exact signup
// operation, original flow and record-omitted profile are mandatory. This does
// no IO, authorization, possession or authoritative history check.
func NewSignupRecovery(q identity.RecoveryQuery, flow identity.PreAuthTransactionID) (SignupRecovery, error) {
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return SignupRecovery{}, ErrPasswordWork
	}
	if _, err := identity.ParsePreAuthTransactionID(string(flow)); err != nil {
		return SignupRecovery{}, ErrPasswordWork
	}
	if !boundedChangeText(string(q.TenantID)) || !boundedChangeText(string(q.ActorID)) || q.OperationID != "identity.password.signup" || q.RecordID != "" || q.LinkMode != 0 || q.UserID != "" || q.AnonymousFlowID != string(flow) {
		return SignupRecovery{}, ErrPasswordWork
	}
	switch q.ActorKind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return SignupRecovery{}, ErrPasswordWork
	}
	return SignupRecovery{query: q, flow: flow}, nil
}

// Bindings returns scalar copies for explicit trusted transport/persistence
// projection. Current disclosure policy and exact retained primary history must
// independently match; this method cannot authorize disclosure or reexecution.
func (r SignupRecovery) Bindings() (identity.RecoveryQuery, identity.PreAuthTransactionID, error) {
	if _, err := NewSignupRecovery(r.query, r.flow); err != nil {
		return identity.RecoveryQuery{}, "", err
	}
	return r.query, r.flow, nil
}

// SignupRecoveryRequest carries original cookie possession and fresh trusted
// provenance without a password, address, retry key or secret-bearing command.
// The native owner must admit retained custody even after flow consumption or
// expiry; recovery is not a new signup. Caller collections remain immutable
// during the call. Structural validation does not establish possession.
type SignupRecoveryRequest struct {
	Recovery SignupRecovery
	Cookie   auth.BearerCredential
	Caller   authorization.DecisionContext
	Origin   string
	Network  string
	Device   string
}

// Validate checks bounded shape and original actor/tenant/action agreement only.
// It neither reads history nor compares the cookie with its retained digest.
func (r SignupRecoveryRequest) Validate() error {
	q, _, err := r.Recovery.Bindings()
	if err != nil || q.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || q.ActorKind != r.Caller.Request.Subject.Kind || r.Caller.Request.Action != "identity.password.signup" || validateSigninProvenance(q.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil {
		return ErrPasswordWork
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// SignupResult is a closed original outcome, not proof of current validity.
// VerificationRequired describes selected deployment policy, never whether an
// account already exists. That arm omits subject and all session metadata; an
// eligible new registration and suppressed collision must be indistinguishable.
// A committed acknowledgement may also omit sessions when issuance is disabled.
// SubjectID may be projected only under independent native disclosure authority,
// not merely because creation was attempted. IDs/correlation are not authority.
//
// Session is omitted unless session issuance actually committed. SessionID may
// retain authorized historical identity after its live payload is deleted;
// never fabricate a partial Session. Optional fresh token and CSRF share their
// native owners' reveal-once custody. Cookie.Value remains empty for trusted HTTP
// delivery. Error/cancellation/replay/recovery must omit credentials and cookie
// metadata. Check the error and Outcome separately; Unknown does not mean denial
// or rollback. Replayed marks a retained observation, not current authentication.
// RetryAfter is nonnegative and positive only for InProgress. Zero is invalid.
type SignupResult struct {
	Outcome              identity.CommitOutcome
	VerificationRequired bool
	SubjectID            identity.UserID
	SessionID            string
	Session              session.IssueResult
	CSRFToken            session.CSRFToken
	Recovery             SignupRecovery
	Replayed             bool
	RetryAfter           time.Duration
}

// Validate checks closed shape without IO, token disclosure or authentication.
// It cannot establish enumeration-safe timing or current disclosure permission;
// the native workflow owns those, including error/cancellation withholding.
func (r SignupResult) Validate() error {
	q, _, err := r.Recovery.Bindings()
	if err != nil || r.RetryAfter < 0 || r.RetryAfter > 0 && r.Outcome != identity.CommitOutcomeInProgress {
		return ErrPasswordWork
	}
	switch r.Outcome {
	case identity.CommitOutcomeCommitted:
		if r.SubjectID != "" && !boundedChangeText(string(r.SubjectID)) || r.VerificationRequired && r.SubjectID != "" {
			return ErrPasswordWork
		}
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
		if r.VerificationRequired || r.SubjectID != "" || r.Session.CommandID != "" {
			return ErrPasswordWork
		}
	default:
		return ErrPasswordWork
	}
	i := r.Session
	if i.CommandID == "" {
		if r.SessionID != "" || r.CSRFToken != (session.CSRFToken{}) || i.CommitOutcome != identity.CommitOutcomeInvalid || i.Session != (session.Session{}) || i.Token != (session.Token{}) || !emptySigninCookie(i.Cookie) || i.Replayed || i.RetryAfter != 0 {
			return ErrPasswordWork
		}
		return nil
	}
	if r.VerificationRequired || !boundedChangeText(string(r.SubjectID)) || !boundedChangeText(r.SessionID) || i.CommandID != q.CommandID || i.CommitOutcome != identity.CommitOutcomeCommitted || i.Replayed != r.Replayed || i.RetryAfter != 0 || i.Cookie.Value != "" || i.Cookie.Raw != "" || len(i.Cookie.Unparsed) != 0 {
		return ErrPasswordWork
	}
	hasToken, hasCSRF := i.Token != (session.Token{}), r.CSRFToken != (session.CSRFToken{})
	if hasToken != hasCSRF || r.Replayed && hasToken || !hasToken && !emptySigninCookie(i.Cookie) {
		return ErrPasswordWork
	}
	if i.Session == (session.Session{}) {
		if !r.Replayed || hasToken {
			return ErrPasswordWork
		}
	} else {
		b, err := i.Session.Bindings()
		if err != nil || b.SessionID != r.SessionID || b.UserID != r.SubjectID || b.TenantID != q.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" {
			return ErrPasswordWork
		}
	}
	return nil
}

// Format redacts original scope and custody for all diagnostic verbs.
func (SignupRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SignupRecovery(redacted)")
}

// MarshalJSON rejects implicit recovery scope disclosure.
func (SignupRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text/map-key projection.
func (SignupRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts recovery correlation.
func (SignupRecovery) LogValue() slog.Value {
	return slog.StringValue("password.SignupRecovery(redacted)")
}

// Format redacts original cookie and scope.
func (SignupRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SignupRecoveryRequest(redacted)")
}

// MarshalJSON rejects implicit request export.
func (SignupRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text/map-key export.
func (SignupRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts request custody and scope.
func (SignupRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("password.SignupRecoveryRequest(redacted)")
}

// Format redacts outcome correlation and native session custody.
func (SignupResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SignupResult(redacted)")
}

// MarshalJSON rejects implicit result/credential export.
func (SignupResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text/map-key export.
func (SignupResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts result correlation and session custody.
func (SignupResult) LogValue() slog.Value { return slog.StringValue("password.SignupResult(redacted)") }
