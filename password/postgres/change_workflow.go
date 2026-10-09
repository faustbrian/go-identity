package passwordpostgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// ChangeWorkflow binds the native keyed service to the adapter-neutral password
// port. It preserves existing direct Change/Recover signatures; no second
// workflow, journal, provider call, transaction or outcome authority is added.
// It borrows an immutable configured native service, which must outlive calls.
// Calls are concurrency-safe with independently owned secrets. Zero denies.
type ChangeWorkflow struct {
	// Opaque indirection prevents private-wrapper reflection from traversing
	// borrowed runtime owners. No request or mutable secret is retained here.
	native func() *KeyedPasswordChangeService
}

var _ password.ChangeService = (*ChangeWorkflow)(nil)

// NewChangeWorkflow selects an already constructed native keyed service without
// IO or cryptographic work. Required schemas, key retention and native owner
// lifetime remain the caller's deployment responsibilities; construction is not
// a health check. Missing composition never selects the unkeyed service.
func NewChangeWorkflow(native *KeyedPasswordChangeService) (*ChangeWorkflow, error) {
	if native == nil || native.native == nil || native.native.source == nil || native.config == nil || native.crypto == nil {
		return nil, password.ErrPasswordWork
	}
	return &ChangeWorkflow{native: func() *KeyedPasswordChangeService { return native }}, nil
}

// Change forwards the one required request key and unchanged original password,
// bearer, upstream proof and trusted provenance to the sole native workflow.
// Intrinsic request validation is not signed proof validation or authority.
// Native execution owns current admission, screening, hashing, atomic effects,
// original retry outcomes and earlier evidence expiry. No retries, fallback,
// normalization, secret destruction or request retention occur at this boundary.
func (s *ChangeWorkflow) Change(ctx context.Context, r password.ChangeRequest) (password.ChangeResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.ChangeResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.ChangeResult{}, err
	}
	if err := r.Validate(); err != nil {
		return password.ChangeResult{}, err
	}
	result, err := s.native().Change(ctx, PasswordChangeRequest{TenantID: r.TenantID, Session: r.Session, Proof: r.Proof, Password: r.Password, Caller: r.Caller, Network: r.Network}, r.IdempotencyKey)
	return portableChangeResult(result), err
}

// Recover delegates original code-free correlation to native current scoped
// result-access policy. It neither resubmits a password nor reveals or renews
// authentication material. Unknown remains unknown; standard cancellation and
// native typed/redacted outcome errors are preserved unchanged.
func (s *ChangeWorkflow) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ChangeResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.ChangeResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.ChangeResult{}, err
	}
	result, err := s.native().Recover(ctx, q, caller)
	return portableChangeResult(result), err
}

func portableChangeResult(r PasswordChangeResult) password.ChangeResult {
	return password.ChangeResult{CommandID: r.CommandID, Outcome: r.Outcome, CredentialVersion: r.CredentialVersion, AuthorityInvalidated: r.AuthorityInvalidated}
}

// Format redacts implicit traversal of borrowed native owners.
func (ChangeWorkflow) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ChangeWorkflow(redacted)")
}

// MarshalJSON denies implicit runtime composition export.
func (ChangeWorkflow) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit runtime composition export.
func (ChangeWorkflow) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue reports only the fixed redacted diagnostic marker.
func (ChangeWorkflow) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.ChangeWorkflow(redacted)")
}
