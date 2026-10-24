package reference

import (
	"context"
	"fmt"
	"slices"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	native "github.com/faustbrian/go-passkey/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// PasskeyConfiguration explicitly selects existing-account resident UV/ES256
// enrollment and identified signin. Identifier-free signin additionally requires
// the authentication risk policy's PasskeyDiscovery opt-in; no HTTP or signup
// capability is selected.
// The graph supplies its actual password proof, authorization, coordinator,
// counted risk, session reader and cookie-CSRF logout owners. Both primary
// selections need distinct exact enrollment actions and signed proof targets
// in PasswordVerification. Flow and Issuer clocks and Risk.Evaluation must be
// absent for graph injection. Protected selects retained encryption/evidence
// keys and a native command counter policy matching the protected command's
// revision; it is distinct from anonymous authentication admission and accepts
// no caller store. Issuance keys/cookie must match Session read/logout policy.
// All borrowed configuration must remain immutable during construction.
type PasskeyConfiguration struct {
	// Signup independently selects prospective-account registration. Nil keeps
	// existing-account enrollment/signin only; it enables no HTTP capability.
	Signup *PasskeySignupConfiguration
	// KeyedOptions explicitly selects native original-key admission for both
	// enrollment and signin options. Nil preserves existing keyless behavior.
	KeyedOptions *PasskeyKeyedOptionsConfiguration
	// Management independently selects keyed self-label rename. It requires
	// KeyedOptions for the same kernel request-key owner, not another journal.
	Management *PasskeyManagementConfiguration
	// Deletion independently selects signed-proof self-removal backed by this
	// graph's actual configured PasswordReset owner. It requires KeyedOptions;
	// enabling label management is not a prerequisite.
	Deletion                            *PasskeyDeletionConfiguration
	Protocol                            webauthn.Config
	RPNamespace                         string
	OptionsPrimary, RegistrationPrimary passwordpg.ActionPrimaryConfig
	Protected                           riskpg.Config
	Flow                                session.PreAuthIssuerConfig
	Issuer                              session.IssuerConfig
	CSRF                                session.CSRFKey
	Risk                                risk.AuthenticationAdmissionCustodyConfig
	IdentifierKey                       []byte
	// SessionPredecessor pins the actual installed issuance CHECK lineage.
	// Retain it for this deployment; incompatible later feature histories deny
	// instead of rewriting an already installed passkey migration checksum.
	SessionPredecessor string
}

// PasskeyManagementConfiguration selects an exact signed update proof for
// password-session self management. Configure its target in PasswordVerification.
// Primary.Action must be identity.passkey.update; CSRF keys must be absent for
// graph injection. Cookie and bearer native profiles remain explicit. Selection
// does not enable HTTP, deletion, passkey-first signup or MFA fallback.
type PasskeyManagementConfiguration struct {
	Primary passwordpg.ActionPrimaryConfig
}

// PasskeyDeletionConfiguration selects an exact identity.passkey.delete proof.
// Primary CSRF keys must be absent for graph injection. Native cookie and bearer
// profiles remain explicit; HTTP selection separately requires cookie transport.
// The graph supplies its concrete PasswordReset recovery owner, not a callback
// asserting recovery eligibility. No signup or browser capability is enabled.
type PasskeyDeletionConfiguration struct {
	Primary passwordpg.ActionPrimaryConfig
}

func (PasskeyDeletionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyDeletionConfiguration(redacted)"))
}

// MarshalJSON prohibits implicit proof/deployment configuration export.
func (PasskeyDeletionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit proof/deployment configuration export.
func (PasskeyDeletionConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (PasskeyManagementConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyManagementConfiguration(redacted)"))
}

// MarshalJSON prohibits implicit deployment/proof-owner export.
func (PasskeyManagementConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit deployment/proof-owner export.
func (PasskeyManagementConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PasskeyKeyedOptionsConfiguration selects the existing kernel request-key
// owner once for passkey options. Its namespace and lookup key must remain stable
// while original mappings are retained. Token and CSRF keys are dedicated
// independent input-correlation keys, not live session/CSRF keys. The graph
// injects its current command-query authorization/clock/revision; applications
// supply no alternate store, journal or request-admission implementation.
// Zero is invalid. Copies share immutable opaque startup-key custody.
type PasskeyKeyedOptionsConfiguration struct {
	state func() passkeyKeyedOptionsInput
}

type passkeyKeyedOptionsInput struct {
	namespace string
	lookupKey [32]byte
	tokenKey  session.DigestKey
	csrfKey   session.CSRFKey
}

// NewPasskeyKeyedOptionsConfiguration copies original-key configuration without
// IO or policy callbacks. Keys must be dedicated nonzero native values. The
// graph subsequently validates namespace/policy through the kernel owner. A
// closure keeps lookup material opaque even when fmt bypasses methods through
// an unexported caller field; configuration never grants execution authority.
func NewPasskeyKeyedOptionsConfiguration(namespace string, lookupKey [32]byte, tokenKey session.DigestKey, csrfKey session.CSRFKey) (PasskeyKeyedOptionsConfiguration, error) {
	if len(namespace) == 0 || len(namespace) > 128 || !utf8.ValidString(namespace) || lookupKey == ([32]byte{}) || tokenKey == (session.DigestKey{}) || csrfKey.Version() == 0 {
		return PasskeyKeyedOptionsConfiguration{}, identity.InvalidInputError{Field: "reference_passkey_keyed_options"}
	}
	selected := passkeyKeyedOptionsInput{namespace, lookupKey, tokenKey, csrfKey}
	return PasskeyKeyedOptionsConfiguration{state: func() passkeyKeyedOptionsInput { return selected }}, nil
}

func (PasskeyKeyedOptionsConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyKeyedOptionsConfiguration(redacted)"))
}

// MarshalJSON prohibits implicit startup-key export.
func (PasskeyKeyedOptionsConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prohibits implicit startup-key export.
func (PasskeyKeyedOptionsConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (PasskeyConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyConfiguration(redacted)"))
}

// MarshalJSON prohibits implicit export of retained startup secrets.
func (PasskeyConfiguration) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits text/map-key export of retained startup secrets.
func (PasskeyConfiguration) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type passkeyState struct {
	tenant      identity.TenantID
	signup      *native.SignupService
	enrollment  *native.EnrollmentService
	signin      *native.SigninService
	inventory   *native.InventoryService
	management  *native.ManagementService
	deletion    *native.DeletionService
	reader      *session.SessionService
	logout      *session.CookieSignOutService
	revoke      *sessionpg.CookieRevokeOneExecutor
	schema      string
	predecessor string
}

// Construct one authority for both the separate native handle and the explicitly
// selected common session paths. Reading never falls back between these owners.
func composePasskeySessionAuthority(c StoreConfiguration, d ReferenceDependencies) (*native.SessionAuthority, error) {
	if c.Passkey == nil {
		return nil, nil
	}
	n := c.Passkey
	authority, err := native.NewSessionAuthority(d.PostgreSQL, native.SessionAuthorityConfig{TenantID: n.Protocol.TenantID, RPNamespace: n.RPNamespace, RPID: n.Protocol.RelyingParty.ID, MaximumDuration: n.Protocol.MaximumDuration})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey"}
	}
	return authority, nil
}

func composePasskey(c StoreConfiguration, d ReferenceDependencies, proofs *passwordVerificationState, evaluation risk.Evaluator, counters *risk.CounterCoordinator, authority *native.SessionAuthority, reset *passwordpg.ResetService, signupEvaluation risk.Evaluator) (*passkeyState, error) {
	if c.Passkey == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_passkey"}
	if c.OTP == nil || c.Session == nil || c.PasswordVerification == nil || c.PasswordSignin == nil || d.PostgreSQL == nil || proofs == nil || proofs.native == nil || counters == nil || authority == nil {
		return nil, invalid
	}
	n, e := *c.Passkey, c.Session.Native.Execution
	tenants := c.Velocity.Tenants
	if c.DurableAdmission != nil {
		tenants = c.DurableAdmission.Tenants
	}
	if !slices.Contains(tenants, string(n.Protocol.TenantID)) || n.Protocol.MaximumDuration > c.OTP.Timeout || n.Flow.Clock != nil || n.Issuer.Clock != nil || n.Issuer.Authority != nil || n.Risk.Evaluation != (risk.Evaluator{}) || n.Flow.PolicyID != e.PolicyID || n.Flow.PolicyVersion != e.PolicyVersion || n.OptionsPrimary.Action != "identity.passkey.register-options" || n.RegistrationPrimary.Action != "identity.passkey.register-verify" || n.Protected.Schema != c.Velocity.Schema || n.Protected.PolicyVersion != e.PolicyVersion || n.Protected.CommandCounters == nil || !n.Protected.EnforceLockouts || !sessionIssuanceMatches(*c.Session, n.Issuer, n.CSRF) {
		return nil, invalid
	}
	for _, primary := range []*passwordpg.ActionPrimaryConfig{&n.OptionsPrimary, &n.RegistrationPrimary} {
		if len(primary.CSRFKeys) != 0 {
			return nil, invalid
		}
		if primary.Transport == session.CredentialCookie {
			if len(c.PasswordVerification.CSRFKeys) == 0 {
				return nil, invalid
			}
			primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
		}
	}
	options, err := passwordpg.NewActionPrimarySource(proofs.native, n.OptionsPrimary)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey_options_primary"}
	}
	registration, err := passwordpg.NewActionPrimarySource(proofs.native, n.RegistrationPrimary)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey_registration_primary"}
	}
	protected, err := riskpg.NewRepository(n.Protected)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey_protected_risk"}
	}
	var keyed native.OptionsRequestConfig
	var selected passkeyKeyedOptionsInput
	var requestKeys kernel.RequestKeyConfig
	if n.KeyedOptions != nil {
		if e.Coordinator.QueryPolicy == nil || n.KeyedOptions.state == nil {
			return nil, invalid
		}
		selected = n.KeyedOptions.state()
		keys, err := kernel.NewRequestKeyConfig(selected.namespace, selected.lookupKey, *e.Coordinator.QueryPolicy)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_keyed_options"}
		}
		keyed, err = native.NewOptionsRequestConfig(keys, selected.tokenKey, selected.csrfKey)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_keyed_options"}
		}
		requestKeys = keys
	}
	enrollment, err := native.NewEnrollmentService(d.PostgreSQL, native.EnrollmentConfig{OptionsRequests: keyed, Protocol: n.Protocol, RPNamespace: n.RPNamespace, Coordinator: e.Coordinator, Authorization: e.Authorization, OptionsSource: options, RegistrationSource: registration, Risk: protected, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey_enrollment"}
	}
	n.Risk.Evaluation = evaluation
	profile := sessionpg.PasskeyAdmissionConfig{GlobalAuthorityID: e.Profile.GlobalAuthorityID, PolicyNamespace: e.Profile.PolicyNamespace, Audience: e.Profile.Audience, RPNamespace: n.RPNamespace}
	signin, err := native.NewSigninService(d.PostgreSQL, native.SigninConfig{OptionsRequests: keyed, Protocol: n.Protocol, Profile: profile, Coordinator: e.Coordinator, Authorization: e.Authorization, Clock: e.Clock, Flow: n.Flow, Session: n.Issuer, CSRF: n.CSRF, Repository: e.Repository, Risk: n.Risk, IdentifierKey: n.IdentifierKey})
	if err != nil {
		return nil, fmt.Errorf("reference: passkey signin composition: %w", err)
	}
	var signup *native.SignupService
	if n.Signup != nil {
		selected := *n.Signup
		if selected.Flow.Clock != nil || selected.Flow.PolicyID != e.PolicyID || selected.Flow.PolicyVersion != e.PolicyVersion || selected.Risk.Evaluation != (risk.Evaluator{}) {
			return nil, identity.InvalidInputError{Field: "reference_passkey_signup"}
		}
		selected.Risk.Evaluation = signupEvaluation
		signup, err = native.NewSignupService(d.PostgreSQL, native.SignupConfig{Protocol: n.Protocol, Profile: profile, Coordinator: e.Coordinator, Authorization: e.Authorization, Clock: e.Clock, Flow: selected.Flow, Session: n.Issuer, CSRF: n.CSRF, Repository: e.Repository, Risk: selected.Risk, Counters: n.Protected, OptionsRequests: keyed})
		if err != nil {
			return nil, fmt.Errorf("reference: passkey signup composition: %w", err)
		}
	}
	validation := c.Session.Native.Validation
	validation.Clock = e.Clock
	readProfile := sessionpg.PasskeySessionServiceConfig{Repository: e.Repository, Profile: profile, Validation: validation, Authority: authority}
	reader, err := sessionpg.NewPasskeySessionService(d.PostgreSQL, readProfile)
	if err != nil {
		return nil, invalid
	}
	inventory, err := native.NewInventoryService(d.PostgreSQL, native.InventoryConfig{TenantID: n.Protocol.TenantID, RPNamespace: n.RPNamespace, RPID: n.Protocol.RelyingParty.ID, Passkey: &readProfile, Protocol: webauthnpg.Config{Coordinator: e.Coordinator, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion}, Authorization: e.Authorization, PolicyVersion: e.PolicyVersion, Rate: counters, MaximumDuration: n.Protocol.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	var management *native.ManagementService
	if n.Management != nil {
		primary := n.Management.Primary
		if n.KeyedOptions == nil || primary.Action != "identity.passkey.update" || len(primary.CSRFKeys) != 0 {
			return nil, identity.InvalidInputError{Field: "reference_passkey_management"}
		}
		if primary.Transport == session.CredentialCookie {
			if len(c.PasswordVerification.CSRFKeys) == 0 {
				return nil, identity.InvalidInputError{Field: "reference_passkey_management"}
			}
			primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
		}
		source, err := passwordpg.NewActionPrimarySource(proofs.native, primary)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_management"}
		}
		management, err = native.NewManagementService(d.PostgreSQL, native.ManagementConfig{TenantID: n.Protocol.TenantID, RPNamespace: n.RPNamespace, RPID: n.Protocol.RelyingParty.ID, ProofAudience: primary.Audience, Password: sessionpg.SessionServiceConfig{Repository: e.Repository, Profile: c.PasswordSignin.Native.Profile, Validation: validation}, Source: source, RequestKeys: requestKeys, RequestTokenKey: selected.tokenKey, RequestCSRFKey: selected.csrfKey, Coordinator: e.Coordinator, Authorization: e.Authorization, Risk: protected, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, MaximumDuration: n.Protocol.MaximumDuration})
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_management"}
		}
	}
	var deletion *native.DeletionService
	if n.Deletion != nil {
		primary := n.Deletion.Primary
		if n.KeyedOptions == nil || reset == nil || c.PasswordReset == nil || primary.Action != "identity.passkey.delete" || len(primary.CSRFKeys) != 0 {
			return nil, identity.InvalidInputError{Field: "reference_passkey_deletion"}
		}
		if primary.Transport == session.CredentialCookie {
			if len(c.PasswordVerification.CSRFKeys) == 0 {
				return nil, identity.InvalidInputError{Field: "reference_passkey_deletion"}
			}
			primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
		}
		source, err := passwordpg.NewActionPrimarySource(proofs.native, primary)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_deletion"}
		}
		recovery, err := passwordpg.NewPasskeyRemovalRecoverySource(reset)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_deletion"}
		}
		// The recovery owner binds its password-action policy, not the unrelated
		// session-signout policy used by the graph's common session executor.
		deletion, err = native.NewDeletionService(d.PostgreSQL, native.DeletionConfig{ManagementConfig: native.ManagementConfig{TenantID: n.Protocol.TenantID, RPNamespace: n.RPNamespace, RPID: n.Protocol.RelyingParty.ID, ProofAudience: primary.Audience, Password: sessionpg.SessionServiceConfig{Repository: e.Repository, Profile: c.PasswordSignin.Native.Profile, Validation: validation}, Source: source, RequestKeys: requestKeys, RequestTokenKey: selected.tokenKey, RequestCSRFKey: selected.csrfKey, Coordinator: e.Coordinator, Authorization: e.Authorization, Risk: protected, PolicyID: c.PasswordReset.Native.PolicyID, PolicyVersion: e.PolicyVersion, MaximumDuration: n.Protocol.MaximumDuration}, Recovery: recovery})
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_passkey_deletion"}
		}
	}
	if len(c.Session.CSRFKeys) == 0 {
		return nil, invalid
	}
	revoke, err := sessionpg.NewCookieRevokeOneExecutor(d.PostgreSQL, sessionpg.RevokeOneExecutorConfig{Execution: e, Sessions: reader, Passkey: &sessionpg.PasskeySessionAdmission{Profile: profile, Authority: authority}}, c.Session.CSRFKeys)
	if err != nil {
		return nil, invalid
	}
	base, err := session.NewSignOutService(reader, revoke, session.SignOutConfig{Cookie: c.Session.Native.Cookie, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, MaximumDuration: c.Session.Native.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	logout, err := session.NewCookieSignOutService(base, c.Session.CSRFKeys)
	if err != nil {
		return nil, invalid
	}
	if _, err := (sessionpg.PasskeySigninMigrationSource{Schema: e.Repository.Schema, Version: 1, PreviousConstraint: n.SessionPredecessor}).Load(context.Background()); err != nil {
		return nil, invalid
	}
	return &passkeyState{tenant: n.Protocol.TenantID, signup: signup, enrollment: enrollment, signin: signin, inventory: inventory, management: management, deletion: deletion, reader: reader, logout: logout, revoke: revoke, schema: e.Repository.Schema, predecessor: n.SessionPredecessor}, nil
}
