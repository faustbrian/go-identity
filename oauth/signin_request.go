package oauth

import (
	"context"
	"fmt"
	"net/url"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SigninStartRequest binds the selected existing-account signin to an original
// preauth browser transaction. FlowID/cookie and Remember must match that exact
// primary record; neither their shape nor Caller grants authentication or flow
// possession. Caller is the configured login service acting on that flow, never
// a user selected before provider verification. The native owner authenticates
// original intent, current configuration, policy and risk before issuing state.
// SignupDisabled is required by this profile. Cookie custody is borrowed for
// the bounded call and must not be logged or retained for recovery.
type SigninStartRequest struct {
	TenantID                identity.TenantID
	Provider                ProviderID
	Callback, ErrorCallback ValidatedCallbackURL
	Scopes                  ScopeSet
	SignupDisabled          bool
	IdempotencyKey          identity.IdempotencyKey
	FlowID                  identity.PreAuthTransactionID
	FlowCookie              auth.BearerCredential
	Remember                session.RememberPolicy
	Caller                  authorization.DecisionContext
	// Device is the bounded browser identity established by trusted transport,
	// never a provider claim or arbitrary request-body override. It remains a
	// separate abuse dimension from this one login flow's random identifier.
	Origin, Network, Device string
}

// Validate checks bounded original shape only, without IO, cookie verification,
// authority reads, state issuance or consumption. Remember must already be
// resolved; default inference or lifetime renewal at callback is forbidden.
func (r SigninStartRequest) Validate() error {
	if !identifier(string(r.Provider)) || r.Callback.raw == "" || r.ErrorCallback.raw == "" || !r.Scopes.Valid() || !r.SignupDisabled || r.IdempotencyKey == (identity.IdempotencyKey{}) || !visible(r.Device, 1, 128) {
		return failure(InvalidInput, nil)
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.FlowID)); err != nil {
		return failure(InvalidInput, nil)
	}
	if _, err := r.Remember.Bindings(); err != nil {
		return failure(InvalidInput, nil)
	}
	if err := validateRPBrowser(r.TenantID, r.FlowCookie, r.Origin, r.Network); err != nil {
		return err
	}
	c := r.Caller
	if c.Validate() != nil || c.Request.Tenant != authorization.TenantID(r.TenantID) || c.Request.Subject.Kind != authorization.SubjectServiceAccount || c.Request.Action != "identity.oauth.signin-start" || c.Request.Resource.Type != "identity.anonymous-flow" || string(c.Request.Resource.ID) != string(r.FlowID) {
		return failure(InvalidInput, nil)
	}
	return nil
}

// SigninStartResult transfers one durably issued original authorization
// transaction to its browser. It is not provider authentication or a session.
// RedirectURI carries original state/nonce; never log it. Expiry is not renewed
// by replay or delivery. No raw browser cookie is returned by this operation.
type SigninStartResult struct {
	RedirectURI   url.URL
	TransactionID string
	ExpiresAt     time.Time
}

// SigninStarter supplies native existing-account initiation. Implementations
// preserve original request custody and preauth/Remember binding under bounded
// cancellation-aware calls; they do not delegate domain stores to applications.
type SigninStarter interface {
	SigninStart(context.Context, SigninStartRequest) (SigninStartResult, error)
}

// Format refuses implicit disclosure of browser and original intent custody.
func (SigninStartRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.SigninStartRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed browser custody.
func (SigninStartRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText rejects implicit original intent and credential export.
func (SigninStartRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts original state and nonce in the authorization URL.
func (SigninStartResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.SigninStartResult(redacted)"))
}

// MarshalJSON requires transport to project its explicit authorization result.
func (SigninStartResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText rejects implicit authorization URL export.
func (SigninStartResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
