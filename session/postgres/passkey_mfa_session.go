package postgres

import (
	"context"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// MFAPasskeySessionAuthority is the consumer-owned RP/credential mapping port
// for completed passkey plus confirmed TOTP sessions. It is deliberately
// separate from PasskeySessionAuthority: enrolled TOTP must not be described as
// known-empty MFA. The MFA owner independently verifies the exact confirmed
// enrollment and account factor generation. Observe reads current primary
// mapping evidence; Require locks and compares the original mapping in the
// exact native completion or revocation owner's Work. Both methods honor ctx,
// and Require's caller must hold its actual factor fence before mapping locks,
// matching the native passkey signin/enrollment lock order.
// deny missing/changed authority and retain no Work, callbacks or goroutines.
// Neither authenticates an assertion/factor, mutates, commits or issues tokens.
type MFAPasskeySessionAuthority interface {
	ObserveMFAPasskeySession(context.Context, string, session.Session) (MFAPasskeySessionAuthorityObservation, error)
	RequireMFAPasskeySession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, string, session.Session) error
}

// MFAPasskeySessionAuthorityObservation is current primary mapping evidence,
// not authentication. PasskeyVersion is positive. ReadStartedAt precedes all
// contributing owner IO and ValidUntil is exclusive, no more than20s later.
// Copies, retries and promotion cannot reset this original evidence window.
// Factor authority is intentionally absent: the MFA owner supplies it directly.
type MFAPasskeySessionAuthorityObservation struct {
	PasskeyVersion            uint64
	ReadStartedAt, ValidUntil time.Time
}

// MFAPasskeySessionServiceConfig selects the original RP, borrowed native
// mapping owner and existing session/kernel/policy/MFA primary readers. Pool
// and Authority must outlive calls. Validation owns its clock/key/budget and
// immutable cache envelope policy. No application domain store is accepted.
type MFAPasskeySessionServiceConfig struct {
	Repository Config
	Profile    PasskeyAdmissionConfig
	Validation session.ServiceConfig
	Authority  MFAPasskeySessionAuthority
}

// MFAPasskeySessionAdmission selects the same trusted RP/mapping owner for
// combined session reading and revocation. It grants no authentication and
// cannot replace the native MFA owner's exact current factor checks.
type MFAPasskeySessionAdmission struct {
	Profile   PasskeyAdmissionConfig
	Authority MFAPasskeySessionAuthority
}

// Format redacts borrowed authority and deployment configuration.
func (MFAPasskeySessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAPasskeySessionAdmission(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration disclosure.
func (MFAPasskeySessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts keys and correlated deployment configuration.
func (MFAPasskeySessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAPasskeySessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit borrowed-authority and key disclosure.
func (MFAPasskeySessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type mfaPasskeySessionSelection struct {
	profile   PasskeyAdmissionConfig
	authority MFAPasskeySessionAuthority
}

// NewMFAPasskeySessionService selects only completed passkey/TOTP records.
// Current directory, exact primary credential, RP mapping, session/family,
// authorization and confirmed TOTP enrollment/generation are all mandatory.
// Ordinary passkey/password records cannot enter this profile. Historical
// assertion/continuation expiry is not renewed or reused as current evidence.
// Install the selected MFA/session histories before use. Construction performs
// no IO, migrations, issuance, writes or goroutine creation; pool is borrowed.
func NewMFAPasskeySessionService(pool *database.Pool, c MFAPasskeySessionServiceConfig) (*session.SessionService, error) {
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
	factors, err := mfapg.NewTOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	p := freezePasskeyProfile(c.Profile)
	r := &primarySessionReader{native: native, domain: domain, policy: authority, clock: c.Validation.Clock, mfaFactors: factors, mfaPasskey: &mfaPasskeySessionSelection{p, c.Authority}}
	cacheProfile := nativeAdmissionCacheProfile("native-passkey-confirmed-totp-session-v1", c.Repository.Schema, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.RPNamespace)
	return session.NewProfileSessionService(r, c.Validation, session.AuthenticationVerified, cacheProfile)
}

func passkeyMFASessionAdmission(c PasskeyAdmissionConfig, record session.Session, b identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	s, err := record.Bindings()
	m, me := record.MFAAuthentication().Bindings()
	if err != nil || me != nil || !c.valid() || m.Method != "totp" || s.Authentication.Proof.Purpose != session.PasskeyMFAPrimaryPurpose || string(m.PrimaryCommandID) != string(s.Authentication.Proof.ID) {
		return deny()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return deny()
	}
	a, err := s.Authority.Bindings()
	key, ke := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	factor := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: key, Version: m.FactorAuthorityVersion}}
	if err != nil || ke != nil || a.Factor != factor || !a.Passkey.Present {
		return deny()
	}
	return credentialSessionAdmissionBindings(c.credentialProfile(), record, b, s.SessionID, s.Version, factor, a.Passkey, auth.AssurancePhishingResistant)
}

func mfaPasskeyObservationBounds(o MFAPasskeySessionAuthorityObservation, start, now time.Time) (time.Time, time.Time, error) {
	return passkeyMappingObservationBounds(o.PasskeyVersion, o.ReadStartedAt, o.ValidUntil, start, now)
}
