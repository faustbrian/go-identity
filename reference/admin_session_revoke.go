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

// HTTPAdminSessionRevokeConfiguration opts into the exact single-session
// write using the selected password/TOTP cookie, its existing trusted signin
// origin, and its original stored synchronizer. Leave quota settings empty
// when another selected administrator feature already owns the shared quota.
type HTTPAdminSessionRevokeConfiguration struct {
	PolicyID        string
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
	AdminNamespace  string
	AdminKey        [32]byte
	Denied          func(context.Context, organizationhttp.AdminRateEvent) error
}

func (HTTPAdminSessionRevokeConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPAdminSessionRevokeConfiguration(redacted)"))
}

func (HTTPAdminSessionRevokeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (HTTPAdminSessionRevokeConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type adminSessionRevokeState struct {
	native *session.AdminRevokeService
	adminSessionRevokeTransport
}

// adminSessionRevokeTransport owns the shared quota lifetime and original
// cookie policy for the selected administrative session mutations.
type adminSessionRevokeTransport struct {
	admin     *organizationhttp.AdminRateLimiter
	ownsAdmin bool
	cookie    string
	schema    string
	origin    identityhttp.Origin
	maximum   time.Duration
}

const adminSessionRevokeHistory = "identity_admin_session_revoke"

func validateAdminSessionRevokeSelection(c StoreConfiguration) error {
	h := c.HTTPAdminSessionRevoke
	if h == nil {
		return nil
	}
	return validateAdminSessionMutation(c, *h, "reference_http_admin_session_revoke")
}

func validateAdminSessionMutation(c StoreConfiguration, h HTTPAdminSessionRevokeConfiguration, field string) error {
	invalid := identity.InvalidInputError{Field: field}
	if c.HTTPRate == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil ||
		c.PasswordSignin.TOTP == nil || c.PasswordSignin.PreAuth == nil || c.PasswordSignin.PreAuth.Origin == "" || c.PasswordSignin.Native.Transport != password.CookieSignin ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return invalid
	}
	maxRead := c.Session.Native.Execution.Repository.MaximumDuration
	if h.PolicyID == "" || h.PolicyRevision != authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion) || h.MaximumDuration < maxRead || h.MaximumDuration < time.Millisecond || h.MaximumDuration > 5*time.Second {
		return invalid
	}
	return nil
}

func composeAdminSessionRevoke(c StoreConfiguration, d ReferenceDependencies, rate *httpRateState, candidates []*organizationhttp.AdminRateLimiter) (*adminSessionRevokeState, error) {
	h := c.HTTPAdminSessionRevoke
	if h == nil {
		return nil, nil
	}
	sessions, executor, config, transport, err := composeAdminSessionMutation(c, d, rate, candidates, *h, "reference_http_admin_session_revoke")
	if err != nil {
		return nil, err
	}
	native, err := session.NewAdminRevokeService(sessions, executor, config)
	if err != nil {
		transport.close()
		return nil, err
	}
	return &adminSessionRevokeState{native: native, adminSessionRevokeTransport: transport}, nil
}

func composeAdminSessionMutation(c StoreConfiguration, d ReferenceDependencies, rate *httpRateState, candidates []*organizationhttp.AdminRateLimiter, h HTTPAdminSessionRevokeConfiguration, field string) (*session.SessionService, *sessionpg.AdminRevokeExecutor, session.AdminRevokeConfig, adminSessionRevokeTransport, error) {
	invalid := identity.InvalidInputError{Field: field}
	var config session.AdminRevokeConfig
	var transport adminSessionRevokeTransport
	if rate == nil {
		return nil, nil, config, transport, invalid
	}
	ordinary := c.Session.Native
	login := c.PasswordSignin.Native
	execution := ordinary.Execution
	execution.Authorization = c.OTP.RequestKeys.Policy.Authorization
	execution.PolicyID, execution.PolicyVersion = h.PolicyID, uint64(h.PolicyRevision)
	validation := ordinary.Validation
	validation.Clock = execution.Clock
	sessions, err := sessionpg.NewMFAPasswordSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{
		Repository: execution.Repository, Profile: login.Profile, Validation: validation,
	})
	if err != nil {
		return nil, nil, config, transport, err
	}
	executor, err := sessionpg.NewAdminRevokeExecutor(d.PostgreSQL, sessionpg.AdminRevokeExecutorConfig{
		Execution: execution, Sessions: sessions, Actor: login.Profile, CSRFKey: login.CSRFKey,
	})
	if err != nil {
		return nil, nil, config, transport, err
	}
	cookie, err := login.Issuance.Cookie.DeletionAttributes()
	if err != nil {
		return nil, nil, config, transport, invalid
	}
	admin, owns, err := selectReferenceAdminRate(organizationhttp.AdminRateConfig{
		Shared: rate.backend, Namespace: h.AdminNamespace, Key: h.AdminKey, Denied: h.Denied,
		Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration,
	}, candidates)
	if err != nil {
		return nil, nil, config, transport, invalid
	}
	config = session.AdminRevokeConfig{
		Authorization: execution.Authorization, PolicyID: h.PolicyID, PolicyRevision: h.PolicyRevision, CSRFKey: login.CSRFKey, MaximumDuration: h.MaximumDuration,
	}
	transport = adminSessionRevokeTransport{admin: admin, ownsAdmin: owns, cookie: cookie.Name, origin: identityhttp.Origin(c.PasswordSignin.PreAuth.Origin), schema: execution.Repository.Schema, maximum: h.MaximumDuration}
	return sessions, executor, config, transport, nil
}

func (s *adminSessionRevokeState) close() {
	if s != nil {
		s.adminSessionRevokeTransport.close()
	}
}

func (s adminSessionRevokeTransport) close() {
	if s.ownsAdmin {
		s.admin.Close()
	}
}

func (s *adminSessionRevokeState) AdminSessionRevokeWithAdmission(ctx context.Context, input sessionhttp.AdminSessionRevokeInput, admit func(context.Context, identity.UserID) error) (sessionhttp.AdminSessionRevokeOutput, error) {
	var out sessionhttp.AdminSessionRevokeOutput
	token, err := session.ParseToken(input.Bearer.Token())
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	result, err := s.native.AdminSessionRevokeWithAdmission(ctx, session.AdminSessionRevokeRequest{
		TenantID: input.TenantID, TargetSubjectID: input.TargetSubjectID, SessionID: input.SessionID,
		CommandID: commandID, CorrelationID: string(commandID), Credential: credential, CSRF: input.CSRF,
	}, admit)
	if err != nil {
		return out, err
	}
	return sessionhttp.AdminSessionRevokeOutput{Revoked: result.Revoked, Version: uint64(result.Version)}, nil
}

func (s *Server) adminSessionRevokeOps(network identityhttp.NetworkConfig) ([]identityhttp.OperationDescriptor, error) {
	native := s.state.features.adminSessionRevoke
	if native == nil {
		return nil, nil
	}
	feature, err := sessionhttp.NewAdminSessionRevokeFeature(sessionhttp.AdminSessionRevokeConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{native.origin}, OriginalCookieName: native.cookie,
		Native: native, Rate: native.admin, MaximumDuration: native.maximum,
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

func (s StoreSet) adminSessionRevokeMigrationCatalog(ctx context.Context, existing []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.adminSessionRevoke == nil {
		return existing, nil
	}
	schema := s.state.features.adminSessionRevoke.schema
	history, err := (sessionpg.AdminRevokeMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(existing, migrationHistory{
		namespace: adminSessionRevokeHistory, history: history,
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{{version: 1, schema: schema, constraintValue: "'identity.admin.session-revoke'", constraints: []string{
			"session_revocations.session_revocations_purpose_check",
			"session_revocations.session_revocations_purpose_oidc_v1",
			"session_revocations." + enterpriseOIDCLogoutSessionConstraint,
			"session_revocations." + enterpriseSAMLLogoutStartConstraint,
		}}},
	}), nil
}
