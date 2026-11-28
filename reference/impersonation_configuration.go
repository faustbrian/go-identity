package reference

import (
	"context"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
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
	// Denial adds terminal pending-grant denial and its migration history.
	// It does not expose an HTTP route.
	Denial bool
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

// HTTPImpersonationDenialConfiguration selects the independent HTTPS Deny
// route. With Start/Stop, omit TrustedOrigins to share its origin policy.
// With an existing administrative quota owner, leave AdminNamespace, AdminKey
// and Denied unset to borrow that owner; otherwise supply all three. Denied
// must durably audit the rejection within the shared admission budget.
type HTTPImpersonationDenialConfiguration struct {
	TrustedOrigins []identityhttp.Origin
	AdminNamespace string
	AdminKey       [32]byte
	Denied         func(context.Context, organizationhttp.AdminRateEvent) error
}

func (HTTPImpersonationDenialConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPImpersonationDenialConfiguration(redacted)"))
}
func (HTTPImpersonationDenialConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (HTTPImpersonationDenialConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type impersonationState struct {
	native    *impersonationpg.Service
	keyed     *impersonationpg.KeyedStartService
	origins   []identityhttp.Origin
	cookie    string
	denial    bool
	admin     *organizationhttp.AdminRateLimiter
	ownsAdmin bool
}

func (s *impersonationState) close() {
	if s != nil && s.ownsAdmin {
		_ = s.admin.Close()
	}
}

func validateImpersonationSelection(c StoreConfiguration) error {
	if c.Impersonation == nil && c.HTTPImpersonation == nil && c.HTTPImpersonationDenial == nil {
		return nil
	}
	if c.Impersonation == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil ||
		c.PasswordSignin.TOTP == nil || c.PasswordSignin.Native.Transport != password.CookieSignin ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return identity.InvalidInputError{Field: "reference_impersonation"}
	}
	if c.HTTPImpersonationDenial != nil && (!c.Impersonation.Denial || c.HTTPRate == nil) {
		return identity.InvalidInputError{Field: "reference_http_impersonation_denial"}
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
	newNative := impersonationpg.NewServiceWithSelfStop
	if n.Denial {
		newNative = impersonationpg.NewServiceWithDenial
	}
	native, err := newNative(d.PostgreSQL, nativeConfig, n.Activation)
	if err != nil {
		return nil, fmt.Errorf("reference impersonation native owner: %w", err)
	}
	owner := &impersonationState{native: native, denial: n.Denial}
	if c.HTTPImpersonation == nil && c.HTTPImpersonationDenial == nil {
		return owner, nil
	}
	cookie, err := login.Issuance.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_http_impersonation"}
	}
	owner.cookie = cookie.Name
	if transport := c.HTTPImpersonation; transport != nil {
		if len(transport.TrustedOrigins) == 0 {
			return nil, identity.InvalidInputError{Field: "reference_http_impersonation"}
		}
		keyed, err := impersonationpg.NewKeyedStartService(native, c.OTP.RequestKeys, transport.KeyedStart)
		if err != nil {
			return nil, fmt.Errorf("reference impersonation keyed start owner: %w", err)
		}
		owner.keyed, owner.origins = keyed, slices.Clone(transport.TrustedOrigins)
	}
	return owner, nil
}

func composeImpersonationDenialHTTP(c StoreConfiguration, owner *impersonationState, rate *httpRateState, org *organizationHTTPState, directory *directorySyncState, scim *managedSCIMCreateState) error {
	h := c.HTTPImpersonationDenial
	if h == nil {
		return nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_impersonation_denial"}
	if owner == nil || !owner.denial || c.HTTPRate == nil || rate == nil {
		return invalid
	}
	if owner.keyed == nil {
		if len(h.TrustedOrigins) == 0 {
			return invalid
		}
		owner.origins = slices.Clone(h.TrustedOrigins)
	} else if len(h.TrustedOrigins) != 0 {
		return invalid
	}
	var existing [3]*organizationhttp.AdminRateLimiter
	if org != nil {
		existing[0] = org.admin
	}
	if directory != nil {
		existing[1] = directory.admin
	}
	if scim != nil {
		existing[2] = scim.rate
	}
	var shared *organizationhttp.AdminRateLimiter
	for _, candidate := range existing {
		if candidate == nil {
			continue
		}
		if !candidate.Configured() || shared != nil && shared != candidate {
			return invalid
		}
		shared = candidate
	}
	if shared != nil {
		if h.AdminNamespace != "" || h.AdminKey != ([32]byte{}) || h.Denied != nil {
			return invalid
		}
		owner.admin = shared
		return nil
	}
	admin, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
		Shared: rate.backend, Namespace: h.AdminNamespace, Key: h.AdminKey, Now: time.Now,
		MaximumDuration: c.HTTPRate.MaximumDuration, Denied: h.Denied,
	})
	if err != nil {
		return invalid
	}
	owner.admin, owner.ownsAdmin = admin, true
	return nil
}
