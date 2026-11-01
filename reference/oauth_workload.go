package reference

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpg "github.com/faustbrian/go-oauth-server/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// OAuthWorkloadConfiguration selects configured confidential Basic clients
// only. Native OAuth retains protocol, credential, transaction, audit/outbox and
// current-authority ownership. Session, managed clients, exchange, OIDC and
// device selections are unsupported; they are never silently enabled.
//
// BootstrapTenantIDs is an explicit immutable directory declaration, not an
// inference from admission scopes. Every workload tenant must be declared and
// present in DurableAdmission.Tenants. Protected counters use the same physical
// risk schema. Clocks in Protocol, Coordinator and RequestKeys must be the real
// clock.System value; production composition accepts no test clock override.
// PolicyNamespace must be exclusive to service-account subjects: the public
// authorization scope deliberately has no subject-kind discriminator.
//
// Remaining fields retain oauth/postgres.Config's bounds, key-retention and
// primary-pool obligations. EnvelopeKeys must be a nonnil *keyring.Provider.
// Construction copies configuration; concurrent caller mutation is forbidden.
type OAuthWorkloadConfiguration struct {
	Protocol                           oauth.Config
	Schema                             string
	GlobalAuthorityID, PolicyNamespace string
	BootstrapTenantIDs                 []identity.TenantID
	TokenKeys                          []oauth.TokenDigestKey
	ActiveTokenKeyVersion              uint32
	IntentKey                          [32]byte
	ActiveEnvelopeKeyID                string
	Coordinator                        kernel.CoordinatorConfig
	RequestKeys                        kernel.RequestKeyConfig
	PolicyID                           string
	Counters                           riskpg.Config
}

// HTTPOAuthWorkloadConfiguration independently opts into canonical workload
// token, introspection and revocation routes. At least one must be selected.
// Namespace obeys the HTTP OAuth rate contract; the shared strict HTTPRate
// backend and its MaximumDuration are reused, without a local fallback.
// NewServer requires the issuer's tenant-host binding to equal every selected
// workload tenant; native-only composition is not restricted by HTTP hosts.
type HTTPOAuthWorkloadConfiguration struct {
	Token, Introspect, Revoke bool
	Namespace                 string
}

type oauthWorkloadState struct {
	native      *oauth.Service
	crypto      *envelope.Service
	envelopeKey string
	directory   *kernel.Repository
	authority   *authority.AuthorityStore
	scopes      []authority.AuthorityScope
	global      string
	tenants     []identity.TenantID
	schema      string
	issuer      string
	maximum     time.Duration
	http        *HTTPOAuthWorkloadConfiguration
	rateMaximum time.Duration
}

func (s *storeState) composeOAuthWorkloads(c StoreConfiguration, d ReferenceDependencies) error {
	invalid := identity.InvalidInputError{Field: "reference_oauth_workload"}
	if c.DurableAdmission == nil || d.PostgreSQL == nil || d.DeliverySender != nil || !oauthWorkloadSelection(c) {
		return invalid
	}
	p := c.OAuthWorkload
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || p.Counters.Schema != s.config.Schema || p.Schema == s.config.Schema || p.Schema == "audit" || s.config.Schema == "audit" || p.Coordinator.QueryPolicy == nil || p.Coordinator.AdmissionPolicy == nil {
		return invalid
	}
	if _, ok := p.Protocol.Clock.(clock.System); !ok {
		return invalid
	}
	for _, policy := range []kernel.CommandQueryPolicy{p.RequestKeys.Policy, *p.Coordinator.QueryPolicy, *p.Coordinator.AdmissionPolicy} {
		if _, ok := policy.Clock.(clock.System); !ok || !sameServerAuthorization(policy.Authorization, p.RequestKeys.Policy.Authorization) {
			return invalid
		}
	}
	protocol, err := p.Protocol.Validated()
	if err != nil || protocol.ManagedClients != nil || protocol.WorkloadExchange != nil || protocol.HumanCodeExchange != nil || len(protocol.OIDCScopes.Scopes()) != 0 || len(protocol.SectorRegistrations) != 0 || protocol.Discovery.AuthorizationEndpoint != "" || p.Counters.LockoutMutations != nil || p.Counters.UseIssuer != nil || p.Counters.UseCounters != nil || len(p.Counters.CaptchaCustody) != 0 {
		return invalid
	}
	if len(p.BootstrapTenantIDs) > 256 {
		return invalid
	}
	if _, err := (kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 1016, GlobalAuthorityID: p.GlobalAuthorityID, TenantIDs: p.BootstrapTenantIDs}).Load(context.Background()); err != nil {
		return invalid
	}
	var scopes []authority.AuthorityScope
	seen := make(map[authority.AuthorityScope]bool)
	for _, client := range protocol.Clients {
		if client.Workload == nil || client.Public || client.AuthenticationMethod != "client_secret_basic" || client.DeviceAuthorization || !slices.Contains(p.BootstrapTenantIDs, client.Workload.TenantID()) || s.tenants[string(client.Workload.TenantID())] == nil {
			return invalid
		}
		scope := authority.AuthorityScope{TenantID: authorization.TenantID(client.Workload.TenantID()), PolicyNamespace: p.PolicyNamespace, SubjectID: authorization.SubjectID(client.Workload.ID())}
		if scope.Validate() != nil {
			return invalid
		}
		if !seen[scope] {
			scopes = append(scopes, scope)
			seen[scope] = true
		}
	}
	var httpConfig *HTTPOAuthWorkloadConfiguration
	var rateMaximum time.Duration
	if c.HTTPOAuthWorkload != nil {
		h := *c.HTTPOAuthWorkload
		if s.httpRate == nil || c.HTTPRate == nil || !h.Token && !h.Introspect && !h.Revoke || h.Namespace == "" || h.Introspect && !protocol.OwningClientIntrospection {
			return invalid
		}
		httpConfig, rateMaximum = &h, c.HTTPRate.MaximumDuration
	}
	native, err := oauthpg.NewService(d.PostgreSQL, oauthpg.Config{Protocol: protocol, Schema: p.Schema, WorkloadAuthority: oauthpg.WorkloadAuthorityConfig{GlobalAuthorityID: p.GlobalAuthorityID, PolicyNamespace: p.PolicyNamespace}, TokenKeys: p.TokenKeys, ActiveTokenKeyVersion: p.ActiveTokenKeyVersion, IntentKey: p.IntentKey, ActiveEnvelopeKeyID: p.ActiveEnvelopeKeyID, Coordinator: p.Coordinator, RequestKeys: p.RequestKeys, PolicyID: p.PolicyID, Counters: p.Counters}, keys)
	if err != nil {
		return invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return invalid
	}
	directory, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: protocol.MaximumDuration})
	if err != nil {
		return invalid
	}
	current, err := authority.NewAuthorityStore(d.PostgreSQL.Raw(), protocol.MaximumDuration)
	if err != nil {
		return invalid
	}
	s.features = &featureState{timeout: protocol.MaximumDuration, authorize: p.RequestKeys.Policy.Authorization, oauthWorkload: &oauthWorkloadState{native: native, crypto: crypto, envelopeKey: p.ActiveEnvelopeKeyID, directory: directory, authority: current, scopes: scopes, global: p.GlobalAuthorityID, tenants: slices.Clone(p.BootstrapTenantIDs), schema: p.Schema, issuer: protocol.Issuer.String(), maximum: protocol.MaximumDuration, http: httpConfig, rateMaximum: rateMaximum}}
	return nil
}

// This separate supported lineage must not silently drop a selected human
// workflow or claim compatibility with its already-installed migration suffix.
func oauthWorkloadSelection(c StoreConfiguration) bool {
	if c.APIKey != nil || c.HTTPAPIKey != nil || c.Organization != nil || c.HTTPOrganization != nil || c.Passkey != nil || c.HTTPPasskey != nil || c.OTP != nil || c.Delivery != nil || c.Session != nil || c.PasswordSignin != nil || c.PasswordSignup != nil || c.PasswordReset != nil || c.PasswordVerification != nil || c.PasswordChange != nil || c.Username != nil || c.Email != nil || c.Phone != nil || c.PhoneRemoval != nil || c.PhoneChange != nil || c.PhoneSignin != nil || c.PhoneOTPSignin != nil || c.PhonePasswordReset != nil || c.MagicLink != nil || c.Anonymous != nil || c.MFAEnrollment != nil || c.MFAOTPEnrollment != nil {
		return false
	}
	return c.HTTPPreAuth == nil && c.HTTPSession == nil && c.HTTPEmailSignin == nil && c.HTTPEmailOTPVerification == nil && c.HTTPEmailOTPChange == nil && c.HTTPEmailAddresses == nil && c.HTTPEmailRequests == nil && c.HTTPPhoneVerification == nil && c.HTTPPhoneChange == nil && c.HTTPPhoneRemoval == nil && c.HTTPPhoneSignin == nil && c.HTTPPhoneOTPSignin == nil && c.HTTPPhonePasswordReset == nil && c.HTTPPasswordSignin == nil && c.HTTPPasswordSignup == nil && c.HTTPPasswordReset == nil && c.HTTPPasswordVerification == nil && c.HTTPPasswordChange == nil && c.HTTPUsername == nil && c.HTTPRegistrationVerification == nil && c.HTTPMagicLink == nil && c.HTTPAnonymous == nil && c.HTTPMFA == nil && c.HTTPMFAEnrollment == nil && c.HTTPMFAActiveStepUp == nil && c.HTTPMFARecoveryRegeneration == nil && c.HTTPMFAFactorUpdate == nil && c.HTTPMFADisable == nil && c.HTTPMFAList == nil
}

func (n *oauthWorkloadState) checkDirectory(ctx context.Context) error {
	for _, scope := range n.scopes {
		state, err := n.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: n.global, TenantID: identity.TenantID(scope.TenantID)})
		if err != nil || !state.Enabled {
			return oauthWorkloadFailure(ctx)
		}
	}
	return nil
}

func (n *oauthWorkloadState) check(ctx context.Context) error {
	if err := n.checkDirectory(ctx); err != nil {
		return err
	}
	for _, scope := range n.scopes {
		if _, err := n.authority.Get(ctx, scope); err != nil {
			return oauthWorkloadFailure(ctx)
		}
	}
	return nil
}

func (n *oauthWorkloadState) initialize(ctx context.Context) error {
	if err := n.check(ctx); err != nil {
		return err
	}
	// The keyring and selected reference are immutable. A startup-only managed
	// round trip proves usable custody without issuing a credential or persisting
	// data. Service zeroizes ephemeral data keys; direct provider calls cannot.
	// Subsequent probes still read authority live, but need not generate keys.
	aad, err := envelope.NewContext(map[string]string{"purpose": "identity.reference.oauth-workload.key-readiness"})
	if err != nil {
		return oauthWorkloadFailure(ctx)
	}
	sealed, err := n.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: []byte{1}, KeyReference: n.envelopeKey, Context: aad})
	if err != nil {
		return oauthWorkloadFailure(ctx)
	}
	plain, err := n.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) != 1 || plain[0] != 1 {
		return oauthWorkloadFailure(ctx)
	}
	return ctx.Err()
}

// BootstrapOAuthWorkloads explicitly initializes only the configured machine
// authority scopes at epoch one in one transaction, before Initialize. It is a
// trusted offline operator operation, never an HTTP handler or startup repair.
// Migrations and the public composition stages must already be complete.
// Existing epochs return Conflict and are never reset, even when greater than
// one. Missing/unavailable directory authority denies without initialization.
//
// A commit error returns Unavailable, not success. The operator can reconcile
// by calling Initialize, which reads every actual scope without creating one.
// Requests are bounded by native MaximumDuration and StoreSet's lifetime;
// concurrent bootstrap/Initialize and calls after Close are denied.
func (s StoreSet) BootstrapOAuthWorkloads(ctx context.Context) error {
	w, done, err := s.state.enterFeature(ctx, false)
	if err != nil {
		return err
	}
	defer done()
	state := s.state
	state.mu.Lock()
	n := state.features.oauthWorkload
	if n == nil || state.features.ready || state.features.initializing {
		state.mu.Unlock()
		return identity.UnavailableError{}
	}
	state.features.initializing = true
	state.mu.Unlock()
	defer func() { state.mu.Lock(); state.features.initializing = false; state.mu.Unlock() }()
	if err := n.checkDirectory(w); err != nil {
		return err
	}
	tx, err := state.pool.Raw().Begin(w)
	if err != nil {
		return oauthWorkloadFailure(w)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	for _, scope := range n.scopes {
		if _, err := authority.InitializeAuthority(w, tx, scope, n.maximum); err != nil {
			if errors.Is(err, authority.ErrAuthorityConflict) {
				return identity.ConflictError{}
			}
			return oauthWorkloadFailure(w)
		}
	}
	if err := tx.Commit(w); err != nil {
		return oauthWorkloadFailure(w)
	}
	return nil
}

func oauthWorkloadFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.UnavailableError{}
}

func (OAuthWorkloadConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.OAuthWorkloadConfiguration(redacted)"))
}
func (OAuthWorkloadConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (OAuthWorkloadConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (HTTPOAuthWorkloadConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPOAuthWorkloadConfiguration(redacted)"))
}
func (HTTPOAuthWorkloadConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (HTTPOAuthWorkloadConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
