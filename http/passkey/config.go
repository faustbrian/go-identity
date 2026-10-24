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

// ConditionalSigninService is the optional capability of the same borrowed
// SigninService selected by SigninConfig.Conditional. It must project the
// existing keyed discoverable command, not allocate a new ceremony or retry
// namespace. The native owner retains risk, original expiry and reveal custody.
// Existing SigninService implementations need not implement it when disabled.
type ConditionalSigninService interface {
	KeyedConditionalAuthenticationOptions(context.Context, passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedConditionalOptionsResult, error)
}

// EnrollmentService borrows existing-account keyed options, authenticated
// original rate metadata and one-use native registration. Distinct genuine
// action proofs remain native-owned; this interface authenticates no data.
type EnrollmentService interface {
	KeyedRegistrationOptions(context.Context, passkey.KeyedRegistrationOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error)
	RegistrationRateSource(context.Context, passkey.RegistrationCeremonyRateRequest) (passkey.CeremonyRateSource, error)
	Register(context.Context, passkey.RegistrationCompletion) (webauthn.VerifiedRegistration, error)
}

// SignupService borrows the actual passkey-first native owner. Original flow
// custody, prospective identity, protected admission, protocol verification,
// account creation and session issuance remain native-owned. Rate metadata is
// not authenticated user authority. Calls must be bounded and concurrency-safe.
type SignupService interface {
	KeyedSignupOptions(context.Context, passkey.KeyedSignupOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error)
	SignupRateSource(context.Context, passkey.SignupCeremonyRateRequest) (passkey.CeremonyRateSource, error)
	Signup(context.Context, passkey.SignupCompletion) (passkey.SignupResult, error)
}

// SignupConfig explicitly selects pre-auth passkey-first registration without
// email/password. Original FlowCookie must be __Host-identity_flow; session and
// device cookie names are distinct. Shared rates, device codec and native owner
// are borrowed and must outlive requests. ActorID/revision/audience are trusted
// deployment policy, never browser fields. Now is prompt and concurrency-safe;
// MaximumDuration is 1ms..30s and cannot extend an earlier caller deadline.
// Selection never enables enrollment or accepts ambient session/CSRF authority.
// Device is signed, non-authenticating tenant/origin correlation; the original
// flow cookie, not a device identifier, proves possession of the browser intent.
type SignupConfig struct {
	Network                   identityhttp.NetworkConfig
	Service                   SignupService
	OptionsRate               *identityhttp.AuthRateLimiter
	VerificationRate          *identityhttp.ChallengeVerificationRateLimiter
	Origin                    identityhttp.Origin
	FlowCookie, SessionCookie session.CookiePolicy
	Device                    session.BrowserDeviceConfig
	ActorID                   identity.ActorID
	PolicyRevision            authorization.Revision
	Audience                  string
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

func (SignupConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SignupConfig(redacted)"))
}

// MarshalJSON rejects implicit runtime-owner and key export.
func (SignupConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit deployment-custody export.
func (SignupConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// InventoryService is the native session-authorized safe metadata projection.
// It independently authenticates self-user scope and native read-risk policy;
// transport admission does not replace either owner.
type InventoryService interface {
	List(context.Context, passkey.InventoryRequest) (passkey.InventoryPage, error)
}

// ManagementService is the existing native keyed self-label mutation owner.
// Its original signed proof, request-key admission, current authority and
// protected transaction remain authoritative. Implementations must honor
// bounded contexts and concurrent calls; HTTP supplies no replacement store.
type ManagementService interface {
	Update(context.Context, passkey.UpdateRequest) (passkey.UpdateResult, error)
}

// DeletionService borrows the native signed-proof and original-key removal
// owner. It must atomically enforce current recovery, protocol/reference removal
// and session effects; transport validation does not establish these facts.
// Implementations honor bounded contexts and concurrent calls.
type DeletionService interface {
	Delete(context.Context, passkey.DeleteRequest) (passkey.DeleteResult, error)
}

// DeleteConfig independently selects cookie-authenticated self-removal. Sessions
// and Proofs must be the native deletion owner's real password session and signed
// proof readers. Audience is the session audience; Rate is shared keyed
// rate.secret. Keys are copied, nonzero and version-distinct (at most16).
// Borrowed dependencies must outlive concurrent requests. MaximumDuration is
// 1ms..30s; caller deadlines and current validity cannot be renewed. No device,
// authenticator-local erasure, replacement recovery or session issuance is added.
type DeleteConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Proofs          auth.ReauthenticationSource
	Service         DeletionService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Origin          identityhttp.Origin
	SessionCookie   session.CookiePolicy
	CSRFKeys        []session.CSRFKey
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

func (DeleteConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.DeleteConfig(redacted)"))
}

// MarshalJSON prohibits implicit runtime-owner and key export.
func (DeleteConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner and key export.
func (DeleteConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// UpdateConfig independently selects cookie-authenticated label management.
// Sessions and Proofs must be the native management owner's actual password
// session and signed-proof readers. Audience is the session audience, not an
// override of the native proof audience. Rate is the shared keyed rate.secret
// owner. CSRF keys are copied, nonzero and version-distinct (at most16).
// Dependencies and prompt clock are borrowed, concurrency-safe and bounded.
// MaximumDuration is1ms..30s; no caller deadline or original validity is renewed.
// No device ceremony, deletion, authentication issuance or fallback is selected.
type UpdateConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Proofs          auth.ReauthenticationSource
	Service         ManagementService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Origin          identityhttp.Origin
	SessionCookie   session.CookiePolicy
	CSRFKeys        []session.CSRFKey
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
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
	// DiscoverableOnly requires Discoverable and rejects identified requests.
	// Address is unused; no email/password comparison owner is required.
	DiscoverableOnly bool
	// Conditional explicitly selects outer conditional browser presentation for
	// discoverable options. It requires Discoverable and Service must implement
	// ConditionalSigninService. Identified requests and completion stay unchanged;
	// no third durable mode, browser capability claim or denial fallback is added.
	Conditional     bool
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
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
// options+verify, Inventory selects list, Update selects label rename and
// Delete selects self-removal. Signup explicitly selects the pre-auth variant
// of the same canonical registration pair. Combined Registration+Signup must
// share ingress limits/host/proxy mapping, Origin, session cookie and actual
// rate-owner pointers. The closed mode discriminator never falls back between
// branches. At least one group is required; no conditional UI or MFA fallback
// is selected.
type FeatureConfig struct {
	Registration *RegistrationConfig
	Signup       *SignupConfig
	Signin       *SigninConfig
	Inventory    *InventoryConfig
	Update       *UpdateConfig
	// SessionUpdate explicitly selects current-session UV options/completion
	// at the update route. It is mutually exclusive with the password profile.
	SessionUpdate *SessionUpdateConfig
	Delete        *DeleteConfig
}

func (UpdateConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.UpdateConfig(redacted)"))
}

// MarshalJSON prohibits implicit runtime-owner and key export.
func (UpdateConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit runtime-owner and key export.
func (UpdateConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

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
