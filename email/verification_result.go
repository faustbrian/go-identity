package email

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RegistrationVerificationService owns original-signup confirmation under the
// require-before-signin profile. It must authenticate original intent, enforce
// current authorization and coordinate one-use consumption with the mutation.
// Calls require bounded contexts; earlier cancellation wins. Recovery observes
// the original command under current query policy, never re-executes it or
// discloses an address/session. This narrow port is not the full email lifecycle
// service or an auto-signin profile. Neither method may infer rollback from IO
// failure; a known commit survives subsequent disclosure failure.
type RegistrationVerificationService interface {
	VerificationConfirm(context.Context, VerificationConfirmRequest) (VerificationConfirmResult, error)
	VerificationRecover(context.Context, VerificationRecoveryRequest) (VerificationRecoveryResult, error)
}

// VerificationRecovery owns immutable original-command correlation, not bearer
// authority or permission to recover. Zero is invalid. Copies permit concurrent
// reads without resources. Current authorization is required on every recovery.
// Closure custody keeps metadata out of recursive private-field diagnostics.
type VerificationRecovery struct{ state *verificationRecoveryState }

type verificationRecoveryState struct{ read func() identity.RecoveryQuery }

// NewVerificationRecovery admits exact signup-confirmation scope and copies
// bounded identifiers. It performs no IO, normalization or authorization.
// Caller-supplied correlation cannot prove that a command exists or committed.
func NewVerificationRecovery(q identity.RecoveryQuery) (VerificationRecovery, error) {
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return VerificationRecovery{}, ErrInvalidVerification
	}
	if !verificationID(string(q.TenantID)) || !verificationID(string(q.UserID)) || !verificationID(q.RecordID) || !verificationID(string(q.ActorID)) || q.OperationID != "identity.email.verification-confirm" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return VerificationRecovery{}, ErrInvalidVerification
	}
	switch q.ActorKind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return VerificationRecovery{}, ErrInvalidVerification
	}
	q.CommandID = identity.CommandID(strings.Clone(string(q.CommandID)))
	q.TenantID = identity.TenantID(strings.Clone(string(q.TenantID)))
	q.UserID = identity.UserID(strings.Clone(string(q.UserID)))
	q.ActorID = identity.ActorID(strings.Clone(string(q.ActorID)))
	q.ActorKind = authorization.SubjectKind(strings.Clone(string(q.ActorKind)))
	q.RecordID = strings.Clone(q.RecordID)
	q.OperationID = "identity.email.verification-confirm"
	return VerificationRecovery{state: &verificationRecoveryState{read: func() identity.RecoveryQuery { return q }}}, nil
}

// Bindings explicitly returns sensitive correlation, without permission or
// primary freshness. Zero returns a constant redacted ErrInvalidVerification.
func (r VerificationRecovery) Bindings() (identity.RecoveryQuery, error) {
	if r.state == nil {
		return identity.RecoveryQuery{}, ErrInvalidVerification
	}
	return r.state.read(), nil
}

// VerificationConfirmResult preserves the observed durable outcome independently
// of later read/disclosure errors. A fresh successful commit returns Address;
// replay and failure return metadata only. A zero address with Committed is valid
// when post-commit disclosure fails: inspect the returned error before using it.
// The registration-only profile never issues Session; the reserved typed field
// is not an implemented auto-signin profile. Explicit projections are sensitive.
type VerificationConfirmResult struct {
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Session    session.IssueResult
	Recovery   VerificationRecovery
	Replayed   bool
	RetryAfter time.Duration
}

// Validate checks structural receipt and disclosure invariants, not current
// authorization, original proof, freshness or successful service execution.
// Invalid zero/unobserved results must be accompanied by a service error.
func (r VerificationConfirmResult) Validate() error {
	q, err := r.Recovery.Bindings()
	if err != nil || !verificationOutcome(r.Outcome, r.RetryAfter) || !emptyVerificationSession(r.Session) {
		return ErrInvalidVerification
	}
	if r.Address != (identity.IdentifierProjection{}) {
		b, err := r.Address.Bindings()
		if err != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Replayed || b.TenantID != q.TenantID || b.UserID != q.UserID || string(b.IdentifierID) != q.RecordID || b.Kind != identity.IdentifierEmail || b.Status != identity.StatusActive || !b.Verified || b.VerificationState != identity.VerificationVerified {
			return ErrInvalidVerification
		}
	}
	return nil
}

// VerificationRecoveryRequest selects original correlation and a trusted current
// caller. Possession grants no access. Caller collections must remain immutable
// during execution; direct redaction does not protect raw private field copies.
type VerificationRecoveryRequest struct {
	Recovery VerificationRecovery
	Caller   authorization.DecisionContext
}

// Validate admits bounded caller structure and exact original actor/tenant/user.
// The native owner must independently enforce current recovery query policy.
func (r VerificationRecoveryRequest) Validate() error {
	q, err := r.Recovery.Bindings()
	if err != nil || validateVerificationCaller(q.TenantID, r.Caller) != nil || string(r.Caller.Request.Subject.ID) != string(q.ActorID) || r.Caller.Request.Subject.Kind != q.ActorKind || (r.Caller.Request.Resource.ID != "" && string(r.Caller.Request.Resource.ID) != string(q.UserID)) {
		return ErrInvalidVerification
	}
	return nil
}

// VerificationRecoveryResult is metadata only. It never carries an address,
// bearer, session or authority to retry the original domain transition.
type VerificationRecoveryResult struct {
	Outcome    identity.CommitOutcome
	Recovery   VerificationRecovery
	RetryAfter time.Duration
}

// Validate requires observed closed outcome, original correlation and a positive
// at-most-one-minute delay only for InProgress. It proves no durable observation.
func (r VerificationRecoveryResult) Validate() error {
	if _, err := r.Recovery.Bindings(); err != nil || !verificationOutcome(r.Outcome, r.RetryAfter) {
		return ErrInvalidVerification
	}
	return nil
}

func verificationOutcome(outcome identity.CommitOutcome, delay time.Duration) bool {
	switch outcome {
	case identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict:
		return delay == 0
	case identity.CommitOutcomeInProgress:
		return delay > 0 && delay <= time.Minute
	default:
		return false
	}
}

func emptyVerificationSession(r session.IssueResult) bool {
	c := r.Cookie
	return r.CommandID == "" && r.CommitOutcome == identity.CommitOutcomeInvalid && r.Session == (session.Session{}) && r.Token == (session.Token{}) && !r.Replayed && r.RetryAfter == 0 && c.Name == "" && c.Value == "" && c.Path == "" && c.Domain == "" && c.Expires.IsZero() && c.RawExpires == "" && c.MaxAge == 0 && !c.Secure && !c.HttpOnly && c.SameSite == 0 && !c.Partitioned && c.Raw == "" && len(c.Unparsed) == 0
}

// Format redacts correlation even for Go-syntax diagnostic formatting.
func (VerificationRecovery) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.VerificationRecovery(redacted)")
}

// LogValue returns only a constant redaction marker.
func (VerificationRecovery) LogValue() slog.Value {
	return slog.StringValue("email.VerificationRecovery(redacted)")
}

// MarshalJSON denies implicit correlation export.
func (VerificationRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (VerificationRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts outcome correlation, address and session custody.
func (VerificationConfirmResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.VerificationConfirmResult(redacted)")
}

// LogValue returns only a constant redaction marker.
func (VerificationConfirmResult) LogValue() slog.Value {
	return slog.StringValue("email.VerificationConfirmResult(redacted)")
}

// MarshalJSON denies implicit result export; transport owns authorized fields.
func (VerificationConfirmResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit result export.
func (VerificationConfirmResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts original correlation and trusted caller data.
func (VerificationRecoveryRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.VerificationRecoveryRequest(redacted)")
}

// LogValue returns only a constant redaction marker.
func (VerificationRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("email.VerificationRecoveryRequest(redacted)")
}

// MarshalJSON denies implicit request export.
func (VerificationRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText denies implicit request export.
func (VerificationRecoveryRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts recovery metadata.
func (VerificationRecoveryResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.VerificationRecoveryResult(redacted)")
}

// LogValue returns only a constant redaction marker.
func (VerificationRecoveryResult) LogValue() slog.Value {
	return slog.StringValue("email.VerificationRecoveryResult(redacted)")
}

// MarshalJSON denies implicit recovery export.
func (VerificationRecoveryResult) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText denies implicit recovery export.
func (VerificationRecoveryResult) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
