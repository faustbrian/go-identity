package reference

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	ssohttp "github.com/faustbrian/go-identity/http/sso"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// DirectorySyncConfiguration opts one exact tenant, organization, and source
// into native directory administration and the generation migration plan. A
// request-selected provider must belong to that organization and satisfy the
// native expected version. The authorization owner must supply current, bounded
// organization-write evidence; read authorization remains graph-owned.
// Selection neither enables HTTP nor starts an ingestion worker.
type DirectorySyncConfiguration struct {
	TenantID                     identity.TenantID
	OrganizationID, ConnectionID string
	PolicyID, KeyReference       string
	Authorization                ssopg.DirectorySyncAuthorization
	// GroupSource independently selects the native SCIM source and its migration
	// history. Add its Apply configuration to bind a direct executor; neither
	// selection starts a worker or adds routes.
	GroupSource *DirectoryGroupSourceConfiguration
	// UserSource selects directory-owned organization membership independently
	// of Teams. With GroupSource selected it borrows the exact same SCIM source.
	UserSource *DirectoryUserSourceConfiguration
}

// HTTPDirectorySyncConfiguration separately enables Start, Status and Cancel.
// With HTTPOrganization selected, leave Rate nil to borrow its exact limiters.
// Otherwise Rate selects the shared backend's directory admission policy
// without enabling any organization HTTP routes.
type HTTPDirectorySyncConfiguration struct {
	Origins []identityhttp.Origin
	Rate    *DirectorySyncHTTPRateConfiguration
}

// DirectorySyncHTTPRateConfiguration supplies deployment namespaces and
// mandatory bounded degradation/denial callbacks. Choose the same deployment
// namespace/key as other canonical actors to retain shared quota identity.
type DirectorySyncHTTPRateConfiguration struct {
	SafeNamespace, AdminNamespace string
	EmergencyMaximumKeys          int
	AdminKey                      [32]byte
	Degraded                      func(context.Context, identityhttp.SafeRateEvent) error
	Denied                        func(context.Context, organizationhttp.AdminRateEvent) error
}

func (DirectorySyncHTTPRateConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.DirectorySyncHTTPRateConfiguration(redacted)"))
}

func (DirectorySyncHTTPRateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectorySyncHTTPRateConfiguration) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

type directorySyncState struct {
	scope    DirectorySyncConfiguration
	pool     *database.Pool
	provider ssopg.ProviderServiceConfig
	csrf     []session.CSRFKey
	origins  []identityhttp.Origin
	safe     *identityhttp.SafeRateLimiter
	admin    *organizationhttp.AdminRateLimiter
	owned    bool
	groups   *directoryGroupSource
	users    *directoryUserSource
}

func (s *directorySyncState) close() {
	if s != nil && s.owned {
		if s.safe != nil {
			s.safe.Close()
		}
		if s.admin != nil {
			s.admin.Close()
		}
	}
}

func validDirectorySelector(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

func composeDirectorySync(c StoreConfiguration, d ReferenceDependencies, crypto *envelope.Service, sessions *sessionState, org *organizationState, orgHTTP *organizationHTTPState, rate *httpRateState) (*directorySyncState, error) {
	if c.DirectorySync == nil {
		return nil, nil
	}
	pool := d.PostgreSQL
	invalid := identity.InvalidInputError{Field: "reference_directory_sync"}
	scope := *c.DirectorySync
	if pool == nil || crypto == nil || sessions == nil || c.Session == nil || c.OTP == nil || c.PasswordSignin == nil || org == nil || c.Organization == nil ||
		!validDirectorySelector(string(scope.TenantID)) || !validDirectorySelector(scope.OrganizationID) || !validDirectorySelector(scope.ConnectionID) ||
		!validDirectorySelector(scope.PolicyID) || !validDirectorySelector(scope.KeyReference) || nilServerDependency(scope.Authorization) {
		return nil, invalid
	}
	if len(c.Session.CSRFKeys) < 1 || len(c.Session.CSRFKeys) > 4 || sessions.cookie == nil {
		return nil, invalid
	}
	lookup := make(map[uint32]session.DigestKey, len(c.Session.Native.Validation.LookupKeys))
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for _, key := range c.Session.Native.Validation.LookupKeys {
		digest, err := probe.Digest(key, "validation")
		if _, exists := lookup[digest.KeyVersion]; err != nil || exists {
			return nil, invalid
		}
		lookup[digest.KeyVersion] = key
	}
	counters, err := riskpg.NewRepository(c.Organization.Counters)
	if err != nil {
		return nil, invalid
	}
	execution := c.Session.Native.Execution
	coordinator, query := c.OTP.Coordinator, c.OTP.RequestKeys.Policy
	// The native administration service is built per browser request. Freeze
	// retained custody here so later caller edits cannot change exact retries.
	coordinator.RetainedFingerprintKeys = maps.Clone(coordinator.RetainedFingerprintKeys)
	if coordinator.FinalAuthentication != nil {
		final := *coordinator.FinalAuthentication
		coordinator.FinalAuthentication = &final
	}
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	providers := ssopg.ProviderServiceConfig{
		Clock: execution.Clock, MaximumDuration: min(5*time.Second, org.maximum, c.Session.Native.MaximumDuration),
		Sessions: sessions.reader, Session: execution.Repository, Profile: c.PasswordSignin.Native.Profile,
		LookupKeys: lookup, Organizations: org.repository, Authorization: execution.Authorization,
		PolicyID: scope.PolicyID, PolicyVersion: execution.PolicyVersion, Counters: counters,
		RequestKeys: c.OTP.RequestKeys, Coordinator: coordinator, Envelope: crypto, KeyReference: scope.KeyReference,
	}
	state := &directorySyncState{scope: scope, pool: pool, provider: providers, csrf: slices.Clone(c.Session.CSRFKeys)}
	if scope.GroupSource != nil {
		state.groups, err = composeDirectoryGroupSource(d, scope, providers, org.teamLifecycle)
		if err != nil {
			return nil, err
		}
		state.scope.GroupSource = nil
	}
	if scope.UserSource != nil {
		state.users, err = composeDirectoryUserSource(d, scope, providers, state.groups)
		if err != nil {
			return nil, err
		}
		state.scope.UserSource = nil
	}
	h := c.HTTPDirectorySync
	if h == nil {
		return state, nil
	}
	if rate == nil || c.HTTPRate == nil || len(h.Origins) == 0 || len(h.Origins) > 128 {
		return nil, invalid
	}
	state.origins = slices.Clone(h.Origins)
	if orgHTTP != nil {
		if h.Rate != nil || !orgHTTP.safe.Configured() || !orgHTTP.admin.Configured() {
			return nil, invalid
		}
		state.safe, state.admin = orgHTTP.safe, orgHTTP.admin
		return state, nil
	}
	if h.Rate == nil {
		return nil, invalid
	}
	config := *h.Rate
	state.owned = true
	state.safe, err = identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: rate.backend, Namespace: config.SafeNamespace, Now: time.Now,
		Degraded: config.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: config.EmergencyMaximumKeys})
	if err == nil {
		state.admin, err = organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: rate.backend, Namespace: config.AdminNamespace, Key: config.AdminKey,
			Now: time.Now, Denied: config.Denied, MaximumDuration: c.HTTPRate.MaximumDuration})
	}
	if err != nil {
		state.close()
		return nil, invalid
	}
	return state, nil
}

func (s *directorySyncState) browser(b ssohttp.DirectoryBrowser) (*ssopg.DirectorySyncService, error) {
	if b.TenantID != s.scope.TenantID || !b.Network.IsValid() {
		return nil, sso.ErrForbidden
	}
	return ssopg.NewDirectorySyncBrowserService(s.pool, s.provider, ssopg.DirectorySyncBrowserConfig{
		TenantID: b.TenantID, Network: b.Network.String(), Cookie: b.Cookie, CSRF: b.CSRF, CSRFKeys: s.csrf,
		OrganizationID: s.scope.OrganizationID, ConnectionID: s.scope.ConnectionID, Authority: s.scope.Authorization,
	})
}

func directoryGeneration(g ssopg.DirectorySyncGeneration) ssohttp.DirectoryGeneration {
	return ssohttp.DirectoryGeneration{ID: g.ID, ProviderID: g.Provider, Version: g.Version, ProviderVersion: g.ProviderVersion, MappingVersion: g.MappingVersion,
		State: string(g.State), Mode: string(g.Mode), Checkpoint: g.Checkpoint, ReadCount: g.ReadCount, AppliedCount: g.AppliedCount, RejectedCount: g.RejectedCount}
}

func (s *directorySyncState) StartDirectorySync(ctx context.Context, b ssohttp.DirectoryBrowser, r ssohttp.DirectoryStartRequest) (ssohttp.DirectoryGeneration, identity.CommandResult, error) {
	service, err := s.browser(b)
	if err != nil {
		return ssohttp.DirectoryGeneration{}, identity.CommandResult{}, err
	}
	result, err := service.Start(ctx, ssopg.DirectorySyncStartRequest{ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion,
		MappingVersion: r.MappingVersion, Mode: ssopg.DirectorySyncMode(r.Mode), Checkpoint: r.Checkpoint, Key: r.Key})
	return directoryGeneration(result.Generation), result.Completion, err
}

func (s *directorySyncState) StatusDirectorySync(ctx context.Context, b ssohttp.DirectoryBrowser, id identity.CommandID) (ssohttp.DirectoryGeneration, error) {
	service, err := s.browser(b)
	if err != nil {
		return ssohttp.DirectoryGeneration{}, err
	}
	result, err := service.Status(ctx, id)
	return directoryGeneration(result), err
}

func (s *directorySyncState) CancelDirectorySync(ctx context.Context, b ssohttp.DirectoryBrowser, id identity.CommandID, version uint64) (ssohttp.DirectoryGeneration, identity.CommandResult, error) {
	service, err := s.browser(b)
	if err != nil {
		return ssohttp.DirectoryGeneration{}, identity.CommandResult{}, err
	}
	result, err := service.CancelExact(ctx, id, version)
	return directoryGeneration(result.Generation), result.Completion, err
}

func (s *Server) appendDirectorySyncFeature(contributions []identityhttp.Feature, network identityhttp.NetworkConfig) ([]identityhttp.Feature, error) {
	f := s.state.features
	if f == nil || f.directorySync == nil || len(f.directorySync.origins) == 0 {
		return contributions, nil
	}
	native := f.directorySync
	feature, err := ssohttp.NewDirectorySyncFeature(ssohttp.DirectorySyncConfig{Network: network, TrustedOrigins: native.origins,
		Cookie: f.session.config.Cookie, Sessions: f.session.reader, Owner: native, SafeRate: native.safe, AdminRate: native.admin, Now: time.Now,
		MaximumDuration: native.provider.MaximumDuration})
	if err != nil {
		return nil, err
	}
	guarded, err := s.guardEnterpriseFeatures([]identityhttp.Feature{feature})
	if err != nil {
		return nil, err
	}
	for i, sibling := range contributions {
		if sibling.ID() == feature.ID() {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: sibling.ID(), Operations: append(sibling.Operations(), guarded[0].Operations()...)})
			if err != nil {
				return nil, err
			}
			contributions[i] = combined
			return contributions, nil
		}
	}
	return append(contributions, guarded[0]), nil
}
