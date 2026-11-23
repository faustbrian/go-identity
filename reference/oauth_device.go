package reference

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
	oauthpg "github.com/faustbrian/go-oauth-server/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// OAuthDeviceConfiguration selects a configured public or Basic device client
// profile over the selected primary password-session and durable admission
// graph. Supply the native bounded policies and retained keyrings; the shared
// risk graph is the sole owner of command-counter digest keys. Supply the
// native policy for the selected protected OAuth actions.
// Managed clients, workload/OIDC profiles and separate session or store owners
// are not selected. Construction performs no IO, and copies its inputs.
// Installing this native history does not select any HTTP route by itself.
type OAuthDeviceConfiguration struct {
	Protocol              oauth.Config
	Schema                string
	TokenKeys             []oauth.TokenDigestKey
	ActiveTokenKeyVersion uint32
	IntentKey             [32]byte
	ActiveEnvelopeKeyID   string
	Coordinator           kernel.CoordinatorConfig
	RequestKeys           kernel.RequestKeyConfig
	PolicyID              string
	Counters              riskpg.Config
	Device                oauthpg.DeviceConfig
}

// HTTPOAuthDeviceConfiguration enables the device authorization and consent
// operations and the device grant on the canonical token endpoint. The issuer
// host must resolve to the device policy's exact tenant, and a shared strict
// HTTP rate store must be selected. No verification UI is included.
type HTTPOAuthDeviceConfiguration struct{ Namespace string }

type oauthDeviceState struct {
	core       *oauth.Service
	native     *device.Service
	directory  *kernel.Repository
	scope      kernel.DirectoryAuthorityQuery
	cookie     session.CookiePolicy
	crypto     *envelope.Service
	keyRef     string
	schema     string
	issuer     string
	maximum    time.Duration
	transport  *HTTPOAuthDeviceConfiguration
	rateBudget time.Duration
}

func (s *storeState) composeOAuthDevice(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState) (*oauthDeviceState, error) {
	if c.OAuthDevice == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_oauth_device"}
	p := c.OAuthDevice
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || sessions == nil || c.PasswordSignin.MFA != nil || len(c.Session.CSRFKeys) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_password_profile"}
	}
	if d.PostgreSQL.Raw().Config().ConnConfig.RuntimeParams["search_path"] != "public" {
		return nil, invalid
	}
	if _, err := sessions.config.Cookie.DeletionAttributes(); err != nil {
		return nil, invalid
	}
	if !slices.Contains(c.OTP.BootstrapTenantIDs, p.Device.Policy.TenantID) || s.tenants[string(p.Device.Policy.TenantID)] == nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_tenant"}
	}
	if p.Schema == "public" || p.Schema == "audit" || p.Schema == "identity" || p.Schema == "identity_password" ||
		p.Schema == s.config.Schema || p.Schema == c.Session.Native.Execution.Repository.Schema ||
		p.Schema == c.OTP.Store.Schema || p.Schema == c.OTP.Store.PreAuth.Schema {
		return nil, invalid
	}
	protocol, err := p.Protocol.Validated()
	if err != nil || !validReferenceDeviceProtocol(protocol, p.Device.Policy, c.OTP.Timeout) {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_protocol"}
	}
	if !sameDeviceAdmission(p, c.OTP.RequestKeys.Policy) {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_admission"}
	}
	counters := p.Counters
	if counters.Schema != s.config.Schema || counters.PolicyVersion != p.RequestKeys.Policy.PolicyVersion || !counters.EnforceLockouts ||
		counters.LockoutMutations != nil || counters.RetainCounterKeyVersions || counters.UseIssuer != nil || counters.UseCounters != nil || len(counters.CaptchaCustody) != 0 {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_counters"}
	}
	if counters.CommandCounters == nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_counters"}
	}
	// The deployed graph supplies the one shared scope for protected limits.
	// A caller cannot provide a second digest identity for the same actions.
	counters.CommandCounters = &risk.CommandCounterPolicyConfig{Policy: counters.CommandCounters.Policy, Keys: s.keys}

	selected := c.Session.Native
	if _, ok := selected.Execution.Clock.(clock.System); !ok {
		return nil, invalid
	}
	selected.Validation.Clock = selected.Execution.Clock
	profile := sessionpg.SessionServiceConfig{Repository: selected.Execution.Repository,
		Profile: sessionpg.IdentifierAdmissionConfig(selected.Execution.Profile), Validation: selected.Validation}
	store, err := oauthpg.NewStore(d.PostgreSQL, oauthpg.Config{
		Schema: p.Schema, Protocol: protocol, Session: profile, CSRFKeys: c.Session.CSRFKeys,
		TokenKeys: p.TokenKeys, ActiveTokenKeyVersion: p.ActiveTokenKeyVersion,
		IntentKey: p.IntentKey, ActiveEnvelopeKeyID: p.ActiveEnvelopeKeyID,
		Coordinator: p.Coordinator, RequestKeys: p.RequestKeys, PolicyID: p.PolicyID,
		Counters: counters, ConsentManagement: true,
	}, keys)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_store"}
	}
	// Use the same primary profile as sign-out; never pass the general-purpose
	// multi-profile reader or its optional positive cache to device review.
	primarySessions, err := sessionpg.NewSessionService(d.PostgreSQL, profile)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_password_profile"}
	}
	core, err := oauth.NewService(protocol, oauth.Dependencies{Store: store, Sessions: primarySessions})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_protocol"}
	}
	native, err := store.DeviceStore(p.Device)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_device_policy"}
	}
	service, err := device.NewService(core, p.Device.Policy, native)
	if err != nil {
		return nil, invalid
	}
	directory, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: protocol.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	state := &oauthDeviceState{core: core, native: service, directory: directory, cookie: selected.Cookie, crypto: crypto,
		scope:  kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.Profile.GlobalAuthorityID, TenantID: p.Device.Policy.TenantID},
		keyRef: p.ActiveEnvelopeKeyID, schema: p.Schema, issuer: protocol.Issuer.String(), maximum: protocol.MaximumDuration}
	if c.HTTPOAuthDevice != nil {
		if s.httpRate == nil || c.HTTPRate == nil || c.HTTPOAuthDevice.Namespace == "" || !protocol.Discovery.Enabled {
			return nil, identity.InvalidInputError{Field: "reference_http_oauth_device"}
		}
		transport := *c.HTTPOAuthDevice
		state.transport, state.rateBudget = &transport, c.HTTPRate.MaximumDuration
	}
	return state, nil
}

func validReferenceDeviceProtocol(p oauth.Config, policy oauth.DevicePolicy, graphBudget time.Duration) bool {
	if _, ok := p.Clock.(clock.System); !ok || p.MaximumDuration > graphBudget || p.ManagedClients != nil ||
		p.WorkloadExchange != nil || p.HumanCodeExchange != nil || p.OwningClientIntrospection ||
		len(p.OIDCScopes.Scopes()) != 0 || len(p.SectorRegistrations) != 0 {
		return false
	}
	if !policy.Enabled || policy.AuthorizationEndpoint != p.Issuer.String()+"/oauth2/device_authorization" ||
		policy.TokenEndpoint != p.Issuer.String()+"/oauth2/token" {
		return false
	}
	for _, client := range p.Clients {
		if !client.DeviceAuthorization || client.Workload != nil {
			return false
		}
	}
	return len(p.Clients) != 0
}

func sameDeviceAdmission(p *OAuthDeviceConfiguration, shared kernel.CommandQueryPolicy) bool {
	if p.Coordinator.QueryPolicy == nil || p.Coordinator.AdmissionPolicy == nil {
		return false
	}
	for _, policy := range []kernel.CommandQueryPolicy{p.RequestKeys.Policy, *p.Coordinator.QueryPolicy, *p.Coordinator.AdmissionPolicy} {
		if _, ok := policy.Clock.(clock.System); !ok || policy.PolicyVersion != shared.PolicyVersion ||
			!sameServerAuthorization(policy.Authorization, shared.Authorization) {
			return false
		}
	}
	return true
}

func (n *oauthDeviceState) check(ctx context.Context) error {
	state, err := n.directory.GetDirectoryAuthority(ctx, n.scope)
	if err != nil || !state.Enabled {
		if err := ctx.Err(); err != nil {
			return err
		}
		return identity.UnavailableError{}
	}
	return nil
}

func (n *oauthDeviceState) initialize(ctx context.Context) error {
	if err := n.check(ctx); err != nil {
		return err
	}
	aad, err := envelope.NewContext(map[string]string{"purpose": "identity.reference.oauth-device.key-readiness"})
	if err != nil {
		return identity.UnavailableError{}
	}
	sealed, err := n.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: []byte{1}, KeyReference: n.keyRef, Context: aad})
	if err != nil {
		return identity.UnavailableError{}
	}
	plain, err := n.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) != 1 || plain[0] != 1 {
		return identity.UnavailableError{}
	}
	return ctx.Err()
}

func (OAuthDeviceConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.OAuthDeviceConfiguration(redacted)"))
}
func (OAuthDeviceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (OAuthDeviceConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
