// Package passkeyhttp supplies explicitly selected cookie-only passkey HTTP
// operations. Base identity/http imports neither this module nor native stores.
package passkeyhttp

import (
	"context"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// SigninService is the borrowed native workflow and original-ceremony source.
// Source reads authenticate original browser/mode custody, not an account or a
// validity lease. Completion independently verifies and consumes atomically.
// Implementations must honor bounded contexts and concurrent calls. No private
// store, source callback, fallback or concrete adapter belongs to this port.
type SigninService interface {
	KeyedAuthenticationOptions(context.Context, passkey.KeyedSigninOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)
	KeyedDiscoverableAuthenticationOptions(context.Context, passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)
	SigninRateSource(context.Context, passkey.SigninCeremonyRateRequest) (passkey.CeremonyRateSource, error)
	DiscoverableSigninRateSource(context.Context, passkey.DiscoverableCeremonyRateRequest) (passkey.CeremonyRateSource, error)
	Signin(context.Context, passkey.SigninCompletion) (passkey.SigninResult, error)
	DiscoverableSignin(context.Context, passkey.DiscoverableSigninCompletion) (passkey.SigninResult, error)
}

// EnrollmentService borrows existing-account keyed options, authenticated
// original rate metadata and one-use native registration. Distinct genuine
// action proofs remain native-owned; this interface authenticates no data.
type EnrollmentService interface {
	KeyedRegistrationOptions(context.Context, passkey.KeyedRegistrationOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error)
	RegistrationRateSource(context.Context, passkey.RegistrationCeremonyRateRequest) (passkey.CeremonyRateSource, error)
	Register(context.Context, passkey.RegistrationCompletion) (webauthn.VerifiedRegistration, error)
}

// InventoryService is the native session-authorized safe metadata projection.
// It independently authenticates self-user scope and native read-risk policy;
// transport admission does not replace either owner.
type InventoryService interface {
	List(context.Context, passkey.InventoryRequest) (passkey.InventoryPage, error)
}

// SigninConfig explicitly selects cookie-only original-flow signin. Borrowed
// Service and shared rates must outlive requests and support concurrent calls.
// Origin/device/flow cookie must match native initiation. FlowCookie must be
// __Host-identity_flow; all credential-cookie names must be distinct. Identified
// input uses the owner's exact email parser before rate/domain
// work. Discoverable is explicit opt-in, never fallback. Native original flow
// owns remember/redirect; this transport accepts neither override. ActorID,
// revision and audience are trusted deployment policy. Now must be prompt and
// concurrency-safe; MaximumDuration is 1ms..30s, earlier deadlines always win.
type SigninConfig struct {
	Network                   identityhttp.NetworkConfig
	Service                   SigninService
	OptionsRate               *identityhttp.AuthRateLimiter
	VerificationRate          *identityhttp.ChallengeVerificationRateLimiter
	Origin                    identityhttp.Origin
	FlowCookie, SessionCookie session.CookiePolicy
	Device                    session.BrowserDeviceConfig
	Address                   email.AddressParser
	Discoverable              bool
	ActorID                   identity.ActorID
	PolicyRevision            authorization.Revision
	Audience                  string
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

// RegistrationConfig selects existing-account cookie-only enrollment. Sessions
// is the actual current session owner; Proofs reads original committed signed
// action proofs by ID, never reconstructed browser fields. Service must use the
// same session/proof/CSRF authority and distinct exact actions for each phase.
// Shared OptionsRate/VerificationRate retain their canonical separate budgets.
// Dependencies are borrowed, concurrency-safe and context-bounded. No signup,
// replacement proof, session issuance or private domain store is configured.
type RegistrationConfig struct {
	Network          identityhttp.NetworkConfig
	Sessions         *session.SessionService
	Proofs           auth.ReauthenticationSource
	Service          EnrollmentService
	OptionsRate      *identityhttp.AuthRateLimiter
	VerificationRate *identityhttp.ChallengeVerificationRateLimiter
	Origin           identityhttp.Origin
	SessionCookie    session.CookiePolicy
	// CSRFKeys are the retained actual session synchronizer keys. They are
	// copied at construction, version-distinct and never used as token-age or
	// proof substitutes. Native completion repeats its own protected check.
	CSRFKeys        []session.CSRFKey
	Device          session.BrowserDeviceConfig
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

// InventoryConfig selects only cookie-authenticated safe self-user listing.
// Sessions and Service must share actual native authority. Shared HTTP safe
// rates do not replace the native inventory owner's read-risk counters. No
// management, credential material, fallback transport or session mutation is
// enabled. Dependencies remain borrowed; all calls are context-bounded.
type InventoryConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         InventoryService
	Rate            *identityhttp.SafeRateLimiter
	SessionCookie   session.CookiePolicy
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// FeatureConfig explicitly selects operation groups; nil exposes neither
// routes nor metadata. Registration selects options+verify, Signin selects
// options+verify and Inventory selects list. At least one group is required.
// No signup, conditional UI, rename/delete or MFA fallback is selected.
type FeatureConfig struct {
	Registration *RegistrationConfig
	Signin       *SigninConfig
	Inventory    *InventoryConfig
}

func (SigninConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SigninConfig(redacted)"))
}
func (RegistrationConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.RegistrationConfig(redacted)"))
}
func (InventoryConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.InventoryConfig(redacted)"))
}
func (FeatureConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.FeatureConfig(redacted)"))
}

// MarshalJSON prohibits implicit runtime-owner export.
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner export.
func (SigninConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON prohibits implicit runtime-owner export.
func (RegistrationConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner export.
func (RegistrationConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON prohibits implicit runtime-owner export.
func (InventoryConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner export.
func (InventoryConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON prohibits implicit runtime-owner export.
func (FeatureConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner export.
func (FeatureConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
