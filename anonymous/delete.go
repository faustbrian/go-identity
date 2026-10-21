package anonymous

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Deleter owns authenticated anonymous self-deletion, never deletion of an
// application-selected target. Native implementations must compose the real
// identity, lifecycle, session, retention, risk, audit and outbox owners. Unknown
// means reconcile the saved original command, not execute a fresh deletion.
type Deleter interface {
	Delete(context.Context, DeletionRequest) (DeletionResult, error)
	RecoverDeletion(context.Context, DeletionRecoveryRequest) (DeletionResult, error)
}

// DeletionResult contains historical outcome only, never current authentication
// or credentials. Save Recovery even on Unknown. A committed result means the
// whole protected transition committed, not that a later retention job ran.
type DeletionResult struct {
	Outcome    identity.CommitOutcome
	Recovery   identity.RecoveryQuery
	Replayed   bool
	RetryAfter time.Duration
}

// DeletionRecoveryRequest proves possession of the original session and CSRF
// custody even after self-revocation. Recovery is metadata-only: expiry or
// deletion never turns that possession back into mutation/access authority.
// Original trusted ingress dimensions must match; no credentials are returned.
type DeletionRecoveryRequest struct {
	Recovery                identity.RecoveryQuery
	Credential              session.Credential
	CSRFToken               session.CSRFToken
	Origin, Network, Device string
}

func (r DeletionRecoveryRequest) Validate() error {
	q := r.Recovery
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if q.OperationID != "identity.anonymous.delete" || !visibleText(string(q.UserID), 128) || string(q.ActorID) != string(q.UserID) || q.ActorKind != authorization.SubjectUser || q.RecordID != string(q.UserID) || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return ErrInvalidInput
	}
	key, err := identity.NewIdempotencyKey([]byte(r.Recovery.CommandID))
	if err != nil {
		return ErrInvalidInput
	}
	return (DeletionRequest{TenantID: r.Recovery.TenantID, Credential: r.Credential, CSRFToken: r.CSRFToken, ExpectedVersion: 1, Reason: "recovery", Origin: r.Origin, Network: r.Network, Device: r.Device, IdempotencyKey: key}).Validate()
}

func (DeletionResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("anonymous.DeletionResult(redacted)"))
}
func (DeletionResult) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (DeletionResult) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (DeletionRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("anonymous.DeletionRecoveryRequest(redacted)"))
}
func (DeletionRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (DeletionRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }

// DeletionRequest presents possession of the original anonymous session, never
// a caller-selected user or permanent-account credential. The native owner
// derives tenant-scoped subject/session identity from its actual primary reader
// and compares ExpectedVersion with the anonymous lifecycle version. Reason is
// a registered policy code, not free-form explanation. Origin, Network and Device
// require trusted ingress; IdempotencyKey retains the exact original attempt.
//
// This selected profile requires the original synchronizer token for either
// transport. Its presence alone proves neither CSRF nor active authentication:
// the owner must compare its digest and exact session/version, authorize self
// deletion, fence current retention/legal hold and commit every required effect.
// Keep inputs immutable throughout a call. Never serialize or log this value.
type DeletionRequest struct {
	TenantID        identity.TenantID
	Credential      session.Credential
	CSRFToken       session.CSRFToken
	ExpectedVersion uint64
	Reason          string
	Origin          string
	Network         string
	Device          string
	IdempotencyKey  identity.IdempotencyKey
}

// Validate bounds structural input without revealing/consuming credentials,
// reading a clock/store, selecting cleanup, or granting mutation authority.
// Zero and overflow versions deny; native policy separately admits the exact
// reason, origin, original session possession and current lifecycle/retention.
func (r DeletionRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || !visibleText(r.Reason, 64) {
		return ErrInvalidInput
	}
	return validateAnonymousPossession(r.TenantID, r.Credential, r.CSRFToken, r.Origin, r.Network, r.Device)
}

func validateAnonymousPossession(tenant identity.TenantID, credential session.Credential, csrf session.CSRFToken, origin, network, device string) error {
	if !visibleText(string(tenant), 128) || credential == (session.Credential{}) || csrf == (session.CSRFToken{}) || !visibleText(origin, 2048) || !visibleText(network, 128) || device != "" && !visibleText(device, 128) {
		return ErrInvalidInput
	}
	if kind := credential.Kind(); kind != session.CredentialBearer && kind != session.CredentialCookie {
		return ErrInvalidInput
	}
	address, err := netip.ParseAddr(network)
	if err != nil || address.Zone() != "" || address.String() != network {
		return ErrInvalidInput
	}
	return nil
}

func (DeletionRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("anonymous.DeletionRequest(redacted)"))
}
func (DeletionRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (DeletionRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (DeletionRequest) LogValue() slog.Value {
	return slog.StringValue("anonymous.DeletionRequest(redacted)")
}
