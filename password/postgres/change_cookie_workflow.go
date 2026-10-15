package passwordpostgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// CookieChangeWorkflow binds the explicitly configured native cookie profile
// to the portable browser port without changing supported direct signatures.
// It adds no journal, provider, transaction or CSRF authority. Borrowed immutable
// native owners must outlive calls; independent request secrets allow concurrent
// calls. Zero denies, never selecting the tokenless bearer workflow.
type CookieChangeWorkflow struct {
	native func() *CookieKeyedPasswordChangeService
}

var _ password.CookieChangeService = (*CookieChangeWorkflow)(nil)

// NewCookieChangeWorkflow selects an already constructed strict cookie owner.
// Construction does no IO and is not schema/readiness verification. Eligible
// CSRF keys, native original-evidence retention and schema installation remain
// explicit deployment responsibilities; no new configuration is inferred.
func NewCookieChangeWorkflow(native *CookieKeyedPasswordChangeService) (*CookieChangeWorkflow, error) {
	if native == nil || native.native == nil {
		return nil, password.ErrPasswordWork
	}
	owner := native.native()
	if owner == nil || owner.native == nil || owner.native.source == nil || owner.config == nil || owner.crypto == nil || owner.csrf == nil {
		return nil, password.ErrPasswordWork
	}
	return &CookieChangeWorkflow{native: func() *CookieKeyedPasswordChangeService { return native }}, nil
}

// Change forwards unchanged original password, bearer, upstream proof, trusted
// scope, sole nested retry key and session-owned token to native cookie change.
// Structural validation is not CSRF/proof permission. No automatic retry,
// normalization, Reveal, secret destruction or tokenless fallback is performed.
// The native owner conserves original outcomes and expiry and atomically fences
// primary synchronizer/proof/risk/password/session effects.
func (s *CookieChangeWorkflow) Change(ctx context.Context, r password.CookieChangeRequest) (password.ChangeResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.ChangeResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.ChangeResult{}, err
	}
	if err := r.Validate(); err != nil {
		return password.ChangeResult{}, err
	}
	input := r.Request
	result, err := s.native().Change(ctx, CookiePasswordChangeRequest{Request: PasswordChangeRequest{TenantID: input.TenantID, Session: input.Session, Proof: input.Proof, Password: input.Password, Caller: input.Caller, Network: input.Network}, IdempotencyKey: input.IdempotencyKey, CSRFToken: r.CSRFToken})
	return portableChangeResult(result), err
}

// Recover forwards scoped code-free original-result access to native policy.
// It resubmits no secret/token and creates no fresh mutation authority. Native
// typed errors, cancellation and ambiguous outcome meanings remain unchanged.
func (s *CookieChangeWorkflow) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ChangeResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.ChangeResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.ChangeResult{}, err
	}
	result, err := s.native().Recover(ctx, q, caller)
	return portableChangeResult(result), err
}

// Format redacts implicit traversal of borrowed runtime owners.
func (CookieChangeWorkflow) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.CookieChangeWorkflow(redacted)")
}

// MarshalJSON denies implicit runtime composition export.
func (CookieChangeWorkflow) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key runtime export.
func (CookieChangeWorkflow) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue emits only a fixed redacted marker.
func (CookieChangeWorkflow) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.CookieChangeWorkflow(redacted)")
}
