package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// PasskeySessionAuthority is the narrow consumer-owned read/fence port supplied
// by the owned passkey PostgreSQL adapter, not an application domain store.
// Both methods must verify the exact trusted RP namespace, credential mapping,
// original passkey key and known-empty MFA key/generation. Observe reads primary
// authority; Require locks and compares it in the given original owner Work.
// Neither method authenticates a new assertion, writes, commits, issues a token,
// retains Work or starts a goroutine. Implementations must honor ctx and support
// concurrent independent calls. Missing, revoked, mismatched or unknown state
// denies; no password/MFA fallback or refreshed original epoch is permitted.
type PasskeySessionAuthority interface {
	ObservePasskeySession(context.Context, string, session.Session) (PasskeySessionAuthorityObservation, error)
	RequirePasskeySession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, string, session.Session) error
}

// PasskeySessionAuthorityObservation reports current primary owner epochs and
// their original positive-evidence window. Both epochs are nonzero and MFA is
// known-empty, not merely absent. ReadStartedAt precedes contributing IO;
// ValidUntil is exclusive and at most20s later. Copies cannot renew that bound.
// This is trusted owner evidence, never a client credential or authentication.
type PasskeySessionAuthorityObservation struct {
	PasskeyVersion, FactorVersion uint64
	ReadStartedAt, ValidUntil     time.Time
}

// PasskeyAdmissionConfig selects trusted native directory/user policy/audience
// and RP namespace. Browser input must never select RPNamespace. The passkey
// adapter must reject a different namespace and verify its owned scope keys.
// Session/kernel keys remain derived by their existing owners. Zero is invalid.
type PasskeyAdmissionConfig struct {
	GlobalAuthorityID, PolicyNamespace, Audience, RPNamespace string
}

func (c PasskeyAdmissionConfig) valid() bool {
	return OTPAdmissionConfig{c.GlobalAuthorityID, c.PolicyNamespace, c.Audience}.valid() && scopeID(c.RPNamespace)
}
func (c PasskeyAdmissionConfig) credentialProfile() IdentifierAdmissionConfig {
	return IdentifierAdmissionConfig{GlobalAuthorityID: c.GlobalAuthorityID, PolicyNamespace: c.PolicyNamespace, Audience: c.Audience, AuthenticationMethod: "passkey", CredentialKind: identity.CredentialPasskey, CredentialOwner: "passkey"}
}
func freezePasskeyProfile(c PasskeyAdmissionConfig) PasskeyAdmissionConfig {
	return PasskeyAdmissionConfig{strings.Clone(c.GlobalAuthorityID), strings.Clone(c.PolicyNamespace), strings.Clone(c.Audience), strings.Clone(c.RPNamespace)}
}

// Format redacts correlated deployment configuration.
func (PasskeyAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeyAdmissionConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration disclosure.
func (PasskeyAdmissionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PasskeySessionServiceConfig composes owned current passkey authority with the
// existing session/kernel/authorization primary readers. Pool and Authority are
// borrowed and must outlive calls; no application transaction/store is accepted.
// The reader owns no resources or goroutines. Validation keeps its key, clock
// and immutable evidence-envelope policy; selected native read budgets must fit.
type PasskeySessionServiceConfig struct {
	Repository Config
	Profile    PasskeyAdmissionConfig
	Validation session.ServiceConfig
	Authority  PasskeySessionAuthority
}

// PasskeySessionAdmission explicitly selects the identical trusted RP and
// borrowed owned authority for revocation. It grants no authentication itself.
type PasskeySessionAdmission struct {
	Profile   PasskeyAdmissionConfig
	Authority PasskeySessionAuthority
}

// Format redacts deployment and borrowed authority configuration.
func (PasskeySessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeySessionAdmission(redacted)"))
}

// MarshalJSON rejects implicit borrowed-authority configuration export.
func (PasskeySessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts session keys and borrowed authority configuration.
func (PasskeySessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeySessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit session/authority configuration export.
func (PasskeySessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type passkeySessionSelection struct {
	profile   PasskeyAdmissionConfig
	authority PasskeySessionAuthority
}

// NewPasskeySessionService selects identified phishing-resistant passkey reads.
// Every kernel, credential, session/family, authorization, RP/passkey and original
// known-empty MFA dimension must remain current. No single-factor password path
// is enabled. Historical ceremony/proof expiry is not renewed after issuance.
// Construct the owned Authority against the same primary database before use.
func NewPasskeySessionService(pool *database.Pool, c PasskeySessionServiceConfig) (*session.SessionService, error) {
	if !c.Profile.valid() || nilIssueDependency(c.Authority) || c.Profile.Audience != c.Validation.Audience || c.Repository.MaximumDuration > c.Validation.MaximumDuration {
		return nil, session.ErrInvalidInput
	}
	native, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, err
	}
	authority, err := policy.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	p := freezePasskeyProfile(c.Profile)
	r := &primarySessionReader{native: native, domain: domain, policy: authority, clock: c.Validation.Clock, passkey: &passkeySessionSelection{p, c.Authority}}
	cacheProfile := nativeAdmissionCacheProfile("native-identified-uv-passkey-session-v1", c.Repository.Schema, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.RPNamespace)
	return session.NewProfileSessionService(r, c.Validation, session.AuthenticationVerified, cacheProfile)
}

func passkeySessionAdmission(c PasskeyAdmissionConfig, record session.Session, b identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	spec, err := record.Bindings()
	if err != nil || !c.valid() || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return deny()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	factorKey, factorErr := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || factorErr != nil || !vector.Factor.Present || !vector.Passkey.Present || vector.Factor.Binding.ScopeKey != factorKey {
		return deny()
	}
	// A present factor dimension here records the original known-empty fence,
	// not secondary-factor completion. The passkey owner checks active_factors=0.
	// The owner also derives/verifies the RP-specific passkey key independently.
	return credentialSessionAdmissionBindings(c.credentialProfile(), record, b, spec.SessionID, spec.Version, vector.Factor, vector.Passkey, auth.AssurancePhishingResistant)
}

func passkeyObservationBounds(o PasskeySessionAuthorityObservation, start, now time.Time) (time.Time, time.Time, error) {
	if o.FactorVersion == 0 {
		return time.Time{}, time.Time{}, session.ErrUnauthenticated
	}
	return passkeyMappingObservationBounds(o.PasskeyVersion, o.ReadStartedAt, o.ValidUntil, start, now)
}

func passkeyMappingObservationBounds(version uint64, readStart, validUntil, start, now time.Time) (time.Time, time.Time, error) {
	if !sessionReadTime(start) || !sessionReadTime(now) || now.Before(start) || version == 0 || !sessionReadTime(readStart) || !sessionReadTime(validUntil) || readStart.After(now) || !validUntil.After(readStart) || validUntil.After(readStart.Add(20*time.Second)) || !now.Before(validUntil) {
		return time.Time{}, time.Time{}, session.ErrUnauthenticated
	}
	if readStart.Before(start) {
		start = readStart
	}
	until := start.Add(20 * time.Second)
	if validUntil.Before(until) {
		until = validUntil
	}
	if !now.Before(until) {
		return time.Time{}, time.Time{}, session.ErrUnauthenticated
	}
	return start, until, nil
}
