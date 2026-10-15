package email

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RemovalPrimaryDisposition explicitly selects the permitted primary effect.
// Zero and unimplemented replacement profiles deny instead of choosing by order.
type RemovalPrimaryDisposition uint8

const (
	// PreserveRemainingPrimary removes a nonprimary address without changing
	// the existing primary selection. It cannot remove the current primary.
	PreserveRemainingPrimary RemovalPrimaryDisposition = iota + 1
	// LeavePrimaryUnassigned permits removing the primary without promoting
	// another address. Remaining verified addresses must actually support the
	// selected signin/reset profile; the native owner checks this atomically.
	LeavePrimaryUnassigned
	// ReplacePrimaryWithVerifiedEmail removes the current primary and promotes
	// only ReplacementPrimary's exact already-verified record in the same commit.
	ReplacePrimaryWithVerifiedEmail
)

// AddressRemoveRequest selects one keyed, freshly authenticated self-removal.
// Expected versions come from the selected address projection; Reason is a
// registered diagnostic code, never free text. Native execution independently
// enforces its reason allowlist, current authority, exact predecessors, remaining
// usable signin/recovery and atomic token/session/lifecycle effects. Caller,
// Network and Primary are trusted composition, not browser authority claims.
// Retrying must retain this complete original input and idempotency key.
type AddressRemoveRequest struct {
	TenantID                    identity.TenantID
	AddressID                   identity.IdentifierID
	ExpectedIdentifierVersion   uint64
	ExpectedVerificationVersion uint64
	Reason                      identity.PolicyReason
	PrimaryDisposition          RemovalPrimaryDisposition
	// ReplacementPrimary must be zero except with ReplacePrimaryWithVerifiedEmail.
	// Its independent versions bind the caller's explicit safe projection.
	ReplacementPrimary  identity.IdentifierPrimarySelection
	RecoveryDisposition RemovalRecoveryPolicy
	IdempotencyKey      identity.IdempotencyKey
	Primary             RequestPrimary
	Caller              authorization.DecisionContext
	Network             string
}

// AddressRemovalService owns keyed protected self-removal and original command
// recovery. Committed results include the exact pending lifecycle cascade;
// removal is not asynchronous cleanup completion. Matching retries preserve the
// original receipt and never consume another proof, retire newer links or issue
// authentication. Recovery requires current query authorization, not an old
// session/proof. Calls are bounded, cancellation-aware and concurrent-safe with
// independent immutable request inputs; consumers supply no domain store.
type AddressRemovalService interface {
	AddressRemove(context.Context, AddressRemoveRequest) (identity.CommandResult, error)
	AddressRemoveRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error)
}

// AddressRemovalRateSource authenticates original request possession before
// shared secret-rate admission. It may retain encrypted original intent in the
// existing request-key journal, never consumes proof, charges mutation counters,
// removes an address or grants fresh authority. Exact retries preserve original
// custody even after session invalidation; the returned user is sensitive.
type AddressRemovalRateSource interface {
	AddressRemoveRateSource(context.Context, AddressRemoveRequest) (identity.UserID, error)
}

// Validate checks bounded intent and intrinsic original-proof structure only.
// It neither authenticates a signature nor consumes proof, queries current
// authority, interprets absence, or renews original proof freshness.
func (r AddressRemoveRequest) Validate() error {
	if _, err := identity.ParseIdentifierID(string(r.AddressID)); err != nil {
		return ErrInvalidRemoval
	}
	if r.ExpectedIdentifierVersion == 0 || r.ExpectedIdentifierVersion == ^uint64(0) || r.ExpectedVerificationVersion == 0 || r.ExpectedVerificationVersion == ^uint64(0) || (r.PrimaryDisposition != PreserveRemainingPrimary && r.PrimaryDisposition != LeavePrimaryUnassigned && r.PrimaryDisposition != ReplacePrimaryWithVerifiedEmail) || r.RecoveryDisposition != PreserveVerifiedEmailRecovery || !removalReason(r.Reason) {
		return ErrInvalidRemoval
	}
	if r.PrimaryDisposition == ReplacePrimaryWithVerifiedEmail {
		if r.ReplacementPrimary.Validate() != nil || r.ReplacementPrimary.ID == r.AddressID {
			return ErrInvalidRemoval
		}
	} else if r.ReplacementPrimary != (identity.IdentifierPrimarySelection{}) {
		return ErrInvalidRemoval
	}
	if err := validateRequestPrimary(r.TenantID, r.Primary, r.Caller, r.Network, nil, r.IdempotencyKey, "identity.email.address-remove"); err != nil {
		return ErrInvalidRemoval
	}
	return nil
}

func removalReason(reason identity.PolicyReason) bool {
	if len(reason) == 0 || len(reason) > 64 || reason[0] < 'a' || reason[0] > 'z' {
		return false
	}
	for _, c := range reason {
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				if c != '-' && c != '_' && c != '.' {
					return false
				}
			}
		}
	}
	return true
}

// Format redacts proof, address and original request correlation.
func (AddressRemoveRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.AddressRemoveRequest(redacted)"))
}

// MarshalJSON refuses implicit original-request export.
func (AddressRemoveRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit original-request export.
func (AddressRemoveRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue omits proof, mailbox and request correlation.
func (AddressRemoveRequest) LogValue() slog.Value {
	return slog.StringValue("email.AddressRemoveRequest(redacted)")
}
