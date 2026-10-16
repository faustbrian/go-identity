package email

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// VerificationSigninRequest explicitly selects original-browser registration
// confirmation followed by email-possession signin. Browser is borrowed signup
// cookie custody, not authentication or an active pre-authentication ticket.
// The native owner must authenticate its original digest, callback and signup
// intent and recover Remember from that intent; no new remember choice is
// accepted here. Origin, Device and Confirmation.Network require trusted
// transport provenance. Device is a current risk input, not identity authority.
// Keep all inputs immutable during the bounded call; never log raw projections.
type VerificationSigninRequest struct {
	Confirmation VerificationConfirmRequest
	Browser      auth.BearerCredential
	Origin       string
	Device       string
}

// Validate checks bounded input structure, not original browser possession,
// grant authentication, current risk/MFA policy or permission to issue a session.
func (r VerificationSigninRequest) Validate() error {
	if r.Confirmation.Validate() != nil || len(r.Origin) > 2048 || !verificationID(r.Device) {
		return ErrInvalidVerification
	}
	if _, err := session.ParseToken(r.Browser.Token()); err != nil {
		return ErrInvalidVerification
	}
	u, err := url.Parse(r.Origin)
	if err != nil || r.Origin != u.Scheme+"://"+u.Host {
		return ErrInvalidVerification
	}
	if _, valid := verificationURL(u, 2048); !valid {
		return ErrInvalidVerification
	}
	return nil
}

// VerificationSigninResult keeps the committed address transition independent
// of a later signin failure or unknown outcome. Verification retains its existing
// verification-only semantics. Issuance and its exact Recovery belong to a
// separately coordinated post-verification command; known verification success
// must never be relabeled rollback if that command fails. Replay/recovery cannot
// issue credentials. Fresh success includes the session owner's reveal-once
// token, value-free cookie attributes and original synchronizer token.
// Always inspect the returned error; projections alone prove no live authority.
type VerificationSigninResult struct {
	Verification VerificationConfirmResult
	Issuance     session.IssueResult
	CSRFToken    session.CSRFToken
	Recovery     identity.RecoveryQuery
}

// Validate checks structural outcome/disclosure consistency only. The native
// owner must establish committed verification, original intent, current policy
// and the linked session transaction. Zero/unknown observation is not success.
func (r VerificationSigninResult) Validate() error {
	if r.Verification.Validate() != nil {
		return ErrInvalidVerification
	}
	if emptyVerificationSession(r.Issuance) {
		if r.CSRFToken != (session.CSRFToken{}) || r.Recovery != (identity.RecoveryQuery{}) {
			return ErrInvalidVerification
		}
		return nil
	}
	v, _ := r.Verification.Recovery.Bindings()
	q, issued := r.Recovery, r.Issuance
	if r.Verification.Outcome != identity.CommitOutcomeCommitted || r.Verification.Replayed || r.Verification.Address == (identity.IdentifierProjection{}) ||
		q.CommandID != issued.CommandID || q.CommandID == v.CommandID || q.TenantID != v.TenantID || q.UserID != v.UserID || q.ActorID != v.ActorID || q.ActorKind != v.ActorKind || q.OperationID != "identity.email.verification-signin" || q.RecordID != string(v.CommandID) || q.AnonymousFlowID != "" || q.LinkMode != 0 || !verificationOutcome(issued.CommitOutcome, issued.RetryAfter) {
		return ErrInvalidVerification
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return ErrInvalidVerification
	}
	if issued.Session != (session.Session{}) {
		s, err := issued.Session.Bindings()
		p, proofErr := issued.Session.MagicLinkAuthentication().Bindings()
		address, addressErr := r.Verification.Address.Bindings()
		if err != nil || proofErr != nil || addressErr != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || s.TenantID != q.TenantID || s.UserID != q.UserID || p.CommandID != q.CommandID || p.IdentifierID != address.IdentifierID || p.IdentifierVersion != address.IdentifierVersion || p.VerificationVersion != address.VerificationVersion {
			return ErrInvalidVerification
		}
	}
	if issued.Token == (session.Token{}) {
		if !reflect.DeepEqual(issued.Cookie, http.Cookie{}) || r.CSRFToken != (session.CSRFToken{}) {
			return ErrInvalidVerification
		}
	} else if issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed || issued.Session == (session.Session{}) || issued.Cookie.Name == "" || issued.Cookie.Value != "" || r.CSRFToken == (session.CSRFToken{}) {
		return ErrInvalidVerification
	}
	return nil
}

// RegistrationVerificationSigninService is independently selected; implementing
// RegistrationVerificationService alone must never enable automatic signin.
// Confirm authenticates original signup/browser custody and commits verification
// before attempting current-policy login. Earlier cancellation wins. A later
// login failure retains the known verification outcome and no credentials.
// Recover authorizes exact current caller scope and returns only original
// command metadata; it never re-executes verification or regenerates a session.
// Services borrow their dependencies and own no unbounded work or goroutines.
type RegistrationVerificationSigninService interface {
	VerificationConfirmAndSignin(context.Context, VerificationSigninRequest) (VerificationSigninResult, error)
	VerificationSigninRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error)
}

// Format hides browser, email, original command and policy custody.
func (VerificationSigninRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.VerificationSigninRequest(redacted)")
}

// LogValue returns no sensitive input projections.
func (VerificationSigninRequest) LogValue() slog.Value {
	return slog.StringValue("email.VerificationSigninRequest(redacted)")
}

// MarshalJSON rejects implicit transport of borrowed browser/grant credentials.
func (VerificationSigninRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit sensitive input export.
func (VerificationSigninRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format hides both durable correlations and all issued credentials.
func (VerificationSigninResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.VerificationSigninResult(redacted)")
}

// LogValue returns no issued credentials or correlated identity metadata.
func (VerificationSigninResult) LogValue() slog.Value {
	return slog.StringValue("email.VerificationSigninResult(redacted)")
}

// MarshalJSON rejects implicit signin result export; the selected transport
// must explicitly reveal token custody only after checking a successful result.
func (VerificationSigninResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit sensitive result export.
func (VerificationSigninResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
