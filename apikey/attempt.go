package apikey

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// VerificationAttemptID is exactly one validated identity.CommandID. Preserve
// it across retries and reconciliation; it grants no authority by itself.
type VerificationAttemptID identity.CommandID

func ParseVerificationAttemptID(raw string) (VerificationAttemptID, error) {
	id, err := identity.ParseCommandID(raw)
	if err != nil {
		return "", ErrInvalid
	}
	return VerificationAttemptID(id), nil
}

type VerificationAttemptState uint8

const (
	VerificationAttemptUnspecified VerificationAttemptState = iota
	VerificationAttemptNotApplicable
	VerificationAttemptNotDebited
	VerificationAttemptDebited
	VerificationAttemptPossibleDebit
)

// AtomicVerificationRequest is one bounded original attempt. Configuration is
// trusted composition; the presented wire value never selects a weaker profile.
// The native owner fingerprints tenant, configuration, exact candidate/digest,
// sorted RequiredPermissions and DebitAmount before any authentication/debit.
type AtomicVerificationRequest struct {
	AttemptID             VerificationAttemptID
	TenantID              identity.TenantID
	ConfigurationID       string
	ConfigurationRevision uint64
	Candidate             KeyID
	Secret                Secret
	// LegacySecret is admitted only under an explicitly server-selected
	// verify-only legacy configuration; supplying both arms is invalid.
	LegacySecret        LegacySecret
	RequiredPermissions []string
	DebitAmount         uint64
}

// Validate checks the finite unlimited shape, not the presented secret against
// storage. Current owner/tenant/permission checks remain mandatory native work.
func (r AtomicVerificationRequest) Validate(c Configuration) error {
	if _, err := ParseVerificationAttemptID(string(r.AttemptID)); err != nil {
		return ErrInvalid
	}
	credentialValid := c.spec.Algorithm == AlgorithmModernHMACSHA256 && r.Secret.state != nil && r.LegacySecret.state == nil || c.spec.Algorithm == AlgorithmLegacySHA256V1 && r.Secret.state == nil && r.LegacySecret.state != nil
	if c.Validate() != nil || !scope(string(r.TenantID), 128) || r.ConfigurationID != c.spec.ID || r.ConfigurationRevision != c.spec.Revision || !credentialValid || !validPermissions(r.RequiredPermissions) || r.DebitAmount != 0 {
		return ErrInvalid
	}
	if r.Candidate != "" {
		_, err := ParseKeyID(string(r.Candidate))
		return err
	}
	return nil
}

// VerificationResult authenticates the credential owner, never the creator as
// a human. It is request-scoped and cannot create a durable/browser session.
// Original authority freshness is preserved through recorded replay results.
type VerificationResult struct {
	Record                                Record
	Owner                                 Owner
	Grant                                 []string
	PolicyVersion                         uint64
	ConfigurationAuthority                ConfigurationAuthorityBinding
	ReadStartedAt, VerifiedAt, ValidUntil time.Time
}

// ValidateAt admits reuse only under the original source freshness and expiry.
// A recorded successful replay is historical after this bound, not fresh
// authentication. Copying/reconciliation cannot extend any timestamp.
func (r VerificationResult) ValidateAt(c Configuration, now time.Time) error {
	if r.Record.Validate(c) != nil || !c.AllowsVerification() || r.Record.Status != KeyActive || r.Owner.Validate() != nil || !r.Owner.SameIdentity(r.Record.Owner) || r.Owner.Version() < r.Record.Owner.Version() || r.PolicyVersion == 0 || r.ConfigurationAuthority.Validate(r.Owner.spec.TenantID, c.spec.ID) != nil || !validPermissions(r.Grant) || r.ReadStartedAt.IsZero() || r.VerifiedAt.Before(r.ReadStartedAt) || r.VerifiedAt.After(now) || r.VerifiedAt.Sub(r.ReadStartedAt) > c.spec.MaximumRead || !r.ValidUntil.After(r.VerifiedAt) || r.ValidUntil.Sub(r.ReadStartedAt) > 20*time.Second || !now.Before(r.ValidUntil) || !now.Before(r.Record.ExpiresAt) {
		return ErrDenied
	}
	for _, permission := range r.Grant {
		if !slices.Contains(r.Record.Grant, permission) {
			return ErrDenied
		}
	}
	return nil
}

// AtomicVerificationResult exposes no principal for denial or ambiguity.
// A successful unlimited profile has NotApplicable, never Debited.
type AtomicVerificationResult struct {
	AttemptID VerificationAttemptID
	// Fingerprint is the exact native coordinator request commitment. Submitted
	// attempts return it even when commitment is unknown, so status inquiry need
	// not retain or resubmit a raw key. Zero is allowed only before submission.
	Fingerprint [32]byte
	// Original retains the exact submitted coordinator scope, including its
	// user/API-key actor or anonymous denial namespace. Current key state must
	// never reconstruct or reinterpret historical routing on reconciliation.
	Original identity.RecoveryQuery
	State    VerificationAttemptState
	Outcome  identity.CommitOutcome
	Result   *VerificationResult
}

func (r AtomicVerificationResult) Validate() error {
	if _, err := ParseVerificationAttemptID(string(r.AttemptID)); err != nil {
		return ErrInvalid
	}
	preSubmission := r.Fingerprint == ([32]byte{}) && r.Original == (identity.RecoveryQuery{}) && r.State == VerificationAttemptNotDebited && (r.Outcome == identity.CommitOutcomeNotCommitted || r.Outcome == identity.CommitOutcomeConflict)
	if !preSubmission && (VerificationReconcileQuery{AttemptID: r.AttemptID, TenantID: r.Original.TenantID, Fingerprint: r.Fingerprint, Original: r.Original}).Validate() != nil {
		return ErrInvalid
	}
	switch r.State {
	case VerificationAttemptNotApplicable, VerificationAttemptDebited:
		if r.Outcome != identity.CommitOutcomeCommitted || r.Result == nil || r.Result.Owner.Validate() != nil || !r.Result.Owner.SameIdentity(r.Result.Record.Owner) || r.Result.PolicyVersion == 0 || !validPermissions(r.Result.Grant) || r.Result.ReadStartedAt.IsZero() || r.Result.VerifiedAt.Before(r.Result.ReadStartedAt) || !r.Result.ValidUntil.After(r.Result.VerifiedAt) || r.Result.ValidUntil.Sub(r.Result.ReadStartedAt) > 20*time.Second {
			return ErrInvalid
		}
		owner := r.Result.Owner.Spec()
		if r.Original.UserID == "" || r.Original.ActorKind != authorization.SubjectAPIKey || owner.Kind != OwnerUser || owner.TenantID != r.Original.TenantID || owner.UserID != r.Original.UserID || KeyID(r.Original.ActorID) != r.Result.Record.ID || r.Result.ConfigurationAuthority.Validate(owner.TenantID, r.Result.Record.ConfigurationID) != nil {
			return ErrInvalid
		}
		record := r.Result.Record
		if record.Status != KeyActive || record.Version == 0 || record.AuthorityVersion == 0 || record.RootID != record.ID || record.RootVersion != record.AuthorityVersion || r.Result.Owner.Version() < record.Owner.Version() || !validPermissions(record.Grant) {
			return ErrInvalid
		}
		for _, permission := range r.Result.Grant {
			if !slices.Contains(record.Grant, permission) {
				return ErrInvalid
			}
		}
	case VerificationAttemptNotDebited:
		if r.Result != nil || r.Outcome != identity.CommitOutcomeNotCommitted && r.Outcome != identity.CommitOutcomeCommitted && r.Outcome != identity.CommitOutcomeUnknown && r.Outcome != identity.CommitOutcomeConflict {
			return ErrInvalid
		}
	case VerificationAttemptPossibleDebit:
		if r.Result != nil || r.Outcome != identity.CommitOutcomeUnknown {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// VerificationReconcileQuery carries no secret or presented digest. It selects
// only the exact existing attempt/fingerprint; reconciliation never verifies or
// debits again and must not refresh a recorded principal's evidence timestamps.
type VerificationReconcileQuery struct {
	AttemptID   VerificationAttemptID
	TenantID    identity.TenantID
	Fingerprint [32]byte
	Original    identity.RecoveryQuery
}

func (q VerificationReconcileQuery) Validate() error {
	if _, err := ParseVerificationAttemptID(string(q.AttemptID)); err != nil {
		return ErrInvalid
	}
	if !scope(string(q.TenantID), 128) || q.Fingerprint == ([32]byte{}) {
		return ErrInvalid
	}
	o := q.Original
	if o.CommandID != identity.CommandID(q.AttemptID) || o.TenantID != q.TenantID || o.OperationID != "identity.apikey.verify" || o.LinkMode != 0 || !scope(string(o.ActorID), 128) {
		return ErrInvalid
	}
	if o.UserID != "" {
		if !scope(string(o.UserID), 128) || o.AnonymousFlowID != "" || o.ActorKind != authorization.SubjectAPIKey || o.RecordID != "" && o.RecordID != string(o.ActorID) {
			return ErrInvalid
		}
	} else if o.AnonymousFlowID != string(q.AttemptID) || o.ActorKind != authorization.SubjectServiceAccount || o.RecordID != "" {
		return ErrInvalid
	}
	return nil
}

type AtomicVerifier interface {
	VerifyAndConsume(context.Context, AtomicVerificationRequest) (AtomicVerificationResult, error)
	ReconcileVerifyAndConsume(context.Context, VerificationReconcileQuery) (AtomicVerificationResult, error)
}

// ErrDebitOutcomeUnknown is specific to an ambiguous submitted positive debit.
// Callers must reconcile its exact attempt, never guess with another attempt.
type ErrDebitOutcomeUnknown struct{ AttemptID VerificationAttemptID }

func (ErrDebitOutcomeUnknown) Error() string { return "apikey: debit outcome unknown" }
func (AtomicVerificationRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.AtomicVerificationRequest(redacted)")
}
func (AtomicVerificationResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.AtomicVerificationResult(redacted)")
}
func (VerificationResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.VerificationResult(redacted)")
}
func (VerificationReconcileQuery) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.VerificationReconcileQuery(redacted)")
}
func (VerificationReconcileQuery) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
