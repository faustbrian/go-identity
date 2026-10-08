package session

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
)

// CSRFRevokeOneExecutor is the explicit owned transactional CSRF profile, not
// the legacy direct executor. It must authenticate original request custody,
// select its own eligible named key, acquire existing source/target mutation
// fences and check the token against exact active primary state on the original
// protected transaction before mutation. Errors abort that transaction; raw
// tokens/keys never enter durable intent, audit or recovery. Implementations
// lacking this profile cannot be selected for CookieSignOutService. Context,
// outcome/recovery and concurrency semantics follow RevokeOneExecutor.
type CSRFRevokeOneExecutor interface {
	ExecuteRevokeOneWithCSRF(context.Context, RevokeOneRequest) (identity.CommandResult, error)
}

// CookieSignOutService selects strict cookie-CSRF self-signout without changing
// the existing trusted direct SignOutService API or public struct shapes. It
// borrows that service and copies 1..4 eligible dedicated CSRF keys. Dependencies
// must outlive calls; immutable instances may be shared concurrently. No stores,
// goroutines, transactions, workflow journals or alternate crypto are created.
type CookieSignOutService struct {
	base *SignOutService
	keys []CSRFKey
}

// NewCookieSignOutService validates explicit cookie composition without IO.
// Keys have distinct positive versions; their current/retained eligibility is
// trusted deployment policy. Caller slice changes cannot alter selection. The
// base executor MUST implement same-transaction CSRF admission for requests
// carrying CSRFToken; a legacy executor is not a supported browser backend.
// Use the owned native factory rather than application-written transaction glue.
func NewCookieSignOutService(base *SignOutService, keys []CSRFKey) (*CookieSignOutService, error) {
	if base == nil || base.sessions == nil || issuerNil(base.executor) || len(keys) < 1 || len(keys) > 4 {
		return nil, ErrInvalidInput
	}
	strict, ok := base.executor.(CSRFRevokeOneExecutor)
	if !ok || issuerNil(strict) {
		return nil, ErrInvalidInput
	}
	for i, key := range keys {
		if key.Version() == 0 {
			return nil, ErrInvalidCSRF
		}
		for _, previous := range keys[:i] {
			if previous.Version() == key.Version() {
				return nil, ErrInvalidCSRF
			}
		}
	}
	return &CookieSignOutService{base: base, keys: append([]CSRFKey(nil), keys...)}, nil
}

// SignOut accepts cookie transport only. HTTP must already enforce exact trusted
// origin, strict cookie parsing and a single canonical CSRF input channel. An
// active caller requires its exact session-bound token and eligible named key;
// successful parsing/prechecking alone never authorizes protected work. The
// executor receives opaque token custody and must recheck under original primary
// fences before mutation. Raw token/key material is never persisted here.
// Absent/inactive credentials retain idempotent success without an impossible
// active-state token check. All other outcomes and commit-dependent cookie
// clearing follow the original SignOutService; no fresh login is required.
func (s *CookieSignOutService) SignOut(ctx context.Context, request SignOutRequest, token CSRFToken) (SignOutResult, error) {
	if s == nil || s.base == nil || len(s.keys) == 0 || ctx == nil || request.Transport != CredentialCookie {
		return SignOutResult{}, ErrInvalidInput
	}
	return s.base.signOut(ctx, request, token, s.keys)
}

// Format prevents traversal of borrowed services and key-selection metadata.
func (CookieSignOutService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.CookieSignOutService(redacted)")
}

// MarshalJSON rejects implicit runtime composition export.
func (CookieSignOutService) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects text and map-key export of runtime composition.
func (CookieSignOutService) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
