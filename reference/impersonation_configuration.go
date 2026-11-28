package reference

import (
	"fmt"
	"slices"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/password"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ImpersonationConfiguration opts into native grant request, independent
// approval and child use. The graph owns ordinary password-plus-TOTP
// sessions, policy authority, counters, journal, audit and outbox. EnvelopeKey
// names retained custody in ReferenceDependencies.EnvelopeKeys.
type ImpersonationConfiguration struct {
	Policy      impersonation.Policy
	Activation  impersonationpg.ActivationConfig
	EnvelopeKey string
}

func (ImpersonationConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.ImpersonationConfiguration(redacted)"))
}
func (ImpersonationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// HTTPImpersonationConfiguration opts into paired HTTPS Start and Stop with
// exact allowed origins. The original cookie name comes from the login owner.
// KeyedStart supplies separate retained request-intent envelope keys.
type HTTPImpersonationConfiguration struct {
	TrustedOrigins []identityhttp.Origin
	KeyedStart     impersonationpg.KeyedStartCustody
}

func (HTTPImpersonationConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPImpersonationConfiguration(redacted)"))
}
func (HTTPImpersonationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type impersonationState struct {
	native  *impersonationpg.Service
	keyed   *impersonationpg.KeyedStartService
	origins []identityhttp.Origin
	cookie  string
}

func validateImpersonationSelection(c StoreConfiguration) error {
	if c.Impersonation == nil && c.HTTPImpersonation == nil {
		return nil
	}
	if c.Impersonation == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil ||
		c.PasswordSignin.TOTP == nil || c.PasswordSignin.Native.Transport != password.CookieSignin ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return identity.InvalidInputError{Field: "reference_impersonation"}
	}
	return nil
}

func composeImpersonation(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, crypto *envelope.Service) (*impersonationState, error) {
	n := c.Impersonation
	if n == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_impersonation"}
	if sessions == nil || n.Policy.Version() != c.OTP.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	login := c.PasswordSignin.Native
	counterConfig := c.PasswordSignin.TOTP.Counters
	counters, err := riskpg.NewRepository(counterConfig)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_impersonation_counters"}
	}
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	// The retained session state intentionally drops key and reader inputs
	// after composition. Derive this narrow primary reader from the same
	// validated source, not from the retained cookie-only configuration.
	ordinary := c.Session.Native
	validation := ordinary.Validation
	validation.Clock = ordinary.Execution.Clock
	nativeConfig := impersonationpg.Config{
		Policy: n.Policy, Authorization: c.OTP.RequestKeys.Policy.Authorization,
		Session: sessionpg.SessionServiceConfig{Repository: ordinary.Execution.Repository, Profile: login.Profile, Validation: validation},
		CSRFKey: login.CSRFKey, Risk: counters, Audit: audit, Lifecycle: lifecycle,
		Envelopes: crypto, EnvelopeKey: n.EnvelopeKey, Coordinator: c.OTP.Coordinator,
	}
	native, err := impersonationpg.NewServiceWithSelfStop(d.PostgreSQL, nativeConfig, n.Activation)
	if err != nil {
		return nil, fmt.Errorf("reference impersonation native owner: %w", err)
	}
	owner := &impersonationState{native: native}
	if transport := c.HTTPImpersonation; transport != nil {
		cookie, err := login.Issuance.Cookie.DeletionAttributes()
		if err != nil || len(transport.TrustedOrigins) == 0 {
			return nil, identity.InvalidInputError{Field: "reference_http_impersonation"}
		}
		keyed, err := impersonationpg.NewKeyedStartService(native, c.OTP.RequestKeys, transport.KeyedStart)
		if err != nil {
			return nil, fmt.Errorf("reference impersonation keyed start owner: %w", err)
		}
		owner.keyed, owner.cookie, owner.origins = keyed, cookie.Name, slices.Clone(transport.TrustedOrigins)
	}
	return owner, nil
}
