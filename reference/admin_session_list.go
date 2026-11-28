package reference

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// HTTPAdminSessionListConfiguration opts into a safe session page. It uses the
// graph's native password/TOTP cookie and current target authorization. Leave
// quota settings unset when a co-selected feature owns the shared admin quota.
type HTTPAdminSessionListConfiguration struct {
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
	AdminNamespace  string
	AdminKey        [32]byte
	Denied          func(context.Context, organizationhttp.AdminRateEvent) error
}

func (HTTPAdminSessionListConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPAdminSessionListConfiguration(redacted)"))
}

func (HTTPAdminSessionListConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (HTTPAdminSessionListConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type adminSessionListState struct {
	native    *session.AdminListService
	admin     *organizationhttp.AdminRateLimiter
	ownsAdmin bool
	cookie    string
	schema    string
	maximum   time.Duration
}

func validateAdminSessionListSelection(c StoreConfiguration) error {
	h := c.HTTPAdminSessionList
	if h == nil {
		return nil
	}
	if c.HTTPRate == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil ||
		c.PasswordSignin.TOTP == nil || c.PasswordSignin.Native.Transport != password.CookieSignin ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return identity.InvalidInputError{Field: "reference_http_admin_session_list"}
	}
	maxRead := c.Session.Native.Execution.Repository.MaximumDuration
	if h.PolicyRevision != authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion) || h.MaximumDuration < maxRead ||
		h.MaximumDuration < time.Millisecond || h.MaximumDuration > 5*time.Second {
		return identity.InvalidInputError{Field: "reference_http_admin_session_list"}
	}
	return nil
}

func composeAdminSessionList(c StoreConfiguration, d ReferenceDependencies, rate *httpRateState, candidates []*organizationhttp.AdminRateLimiter) (*adminSessionListState, error) {
	h := c.HTTPAdminSessionList
	if h == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_admin_session_list"}
	if rate == nil {
		return nil, invalid
	}
	ordinary := c.Session.Native
	login := c.PasswordSignin.Native
	validation := ordinary.Validation
	validation.Clock = ordinary.Execution.Clock
	profile := sessionpg.SessionServiceConfig{Repository: ordinary.Execution.Repository, Profile: login.Profile, Validation: validation}
	sessions, err := sessionpg.NewMFAPasswordSessionService(d.PostgreSQL, profile)
	if err != nil {
		return nil, err
	}
	pages, err := sessionpg.NewRepository(d.PostgreSQL, profile.Repository)
	if err != nil {
		return nil, err
	}
	native, err := session.NewAdminListService(sessions, pages, session.ListConfig{
		Authorization: c.OTP.RequestKeys.Policy.Authorization, PolicyRevision: h.PolicyRevision, MaximumDuration: h.MaximumDuration,
	})
	if err != nil {
		return nil, err
	}
	cookie, err := login.Issuance.Cookie.DeletionAttributes()
	if err != nil {
		return nil, invalid
	}
	admin, owns, err := selectReferenceAdminRate(organizationhttp.AdminRateConfig{
		Shared: rate.backend, Namespace: h.AdminNamespace, Key: h.AdminKey, Denied: h.Denied,
		Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration,
	}, candidates)
	if err != nil {
		return nil, invalid
	}
	return &adminSessionListState{native: native, admin: admin, ownsAdmin: owns, cookie: cookie.Name, schema: profile.Repository.Schema, maximum: h.MaximumDuration}, nil
}

func (s *adminSessionListState) close() {
	if s != nil && s.ownsAdmin {
		s.admin.Close()
	}
}

func (s *Server) adminSessionListOps(network identityhttp.NetworkConfig) ([]identityhttp.OperationDescriptor, error) {
	native := s.state.features.adminSessionList
	if native == nil {
		return nil, nil
	}
	feature, err := sessionhttp.NewAdminSessionListFeature(sessionhttp.AdminSessionListConfig{
		Network: network, OriginalCookieName: native.cookie, Native: native.native, Rate: native.admin, MaximumDuration: native.maximum,
	})
	if err != nil {
		return nil, err
	}
	ops := feature.Operations()
	for i := range ops {
		ops[i].Handler = s.guardSessionLifetime(ops[i].Handler)
	}
	return ops, nil
}

func (s StoreSet) adminSessionListMigrationCatalog(ctx context.Context, existing []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.adminSessionList == nil {
		return existing, nil
	}
	schema := s.state.features.adminSessionList.schema
	labels, err := (sessionpg.UpdateMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	index, err := (sessionpg.ListMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(existing, migrationHistory{
		namespace: "identity_admin_session_list", history: append(labels, index...),
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{
			{version: 1, schema: schema, tables: []string{"session_labels", "session_updates"}},
			{version: 2, schema: schema, tables: []string{"session_owner_audience_order"}},
		},
	}), nil
}
