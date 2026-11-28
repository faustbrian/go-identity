package reference

import (
	"context"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const (
	adminUserBanAction   = "identity.admin.user-ban"
	adminUserUnbanAction = "identity.admin.user-unban"
	adminStatusFreshness = 15 * time.Minute
)

// UserStatusAdministrationConfiguration selects the native status policy and
// durable pending-consumer manifest. The graph supplies request-key, audit,
// outbox, ordinary session, and current authorization owners. Its explicit
// manifest does not acknowledge or run any cascade consumer.
type UserStatusAdministrationConfiguration struct {
	Status                 identity.UserStatusConfig
	Redact                 identity.RedactFunc
	RetentionPolicyVersion uint64
	MaximumCascadeDuration time.Duration
	ConsumerContracts      map[string]kernel.StatusConsumerContract
}

// AdminUserStatusRequest submits one keyed operation using the original
// ordinary password/TOTP credential and its stored synchronizer. TenantID must
// match the primary session. No request field selects the administrator.
type AdminUserStatusRequest struct {
	TenantID                 identity.TenantID
	Bearer                   authentication.BearerCredential
	CSRF                     session.CSRFToken
	Key                      identity.IdempotencyKey
	UserID                   identity.UserID
	ExpectedVersion          uint64
	ExpectedAuthorityVersion uint64
	Reason                   string
	ExpiresAt                time.Time
}

func (AdminUserStatusRequest) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.AdminUserStatusRequest(redacted)"))
}
func (AdminUserStatusRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (AdminUserStatusRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// UserStatusAdministrationService borrows the configuration and lifetime of
// the selected Reference graph. It does not issue or restore credentials.
type UserStatusAdministrationService struct{ state *storeState }

type userStatusAdministrationState struct {
	native      *identity.UserStatusService
	sessions    *session.SessionService
	keys        *kernel.Coordinator
	preparation *kernel.StatusUnitOfWork
	auth        authorization.Service
	clock       clock.Clock
	csrf        session.CSRFKey
	status      identity.UserStatusConfig
	http        *userStatusHTTPState
}

func validateUserStatusAdministrationSelection(c StoreConfiguration) error {
	if h := c.HTTPUserStatusAdministration; h != nil && (c.UserStatusAdministration == nil || c.HTTPRate == nil || !h.Ban && !h.Unban || len(h.TrustedOrigins) < 1 || len(h.TrustedOrigins) > 128) {
		return identity.InvalidInputError{Field: "reference_http_user_status"}
	}
	if c.UserStatusAdministration == nil {
		return nil
	}
	if c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil ||
		c.PasswordSignin.TOTP == nil || c.PasswordSignin.Native.Transport != password.CookieSignin ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil ||
		c.UserStatusAdministration.Status.Query.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
		return identity.InvalidInputError{Field: "reference_user_status_administration"}
	}
	return nil
}

func composeUserStatusAdministration(c StoreConfiguration, d ReferenceDependencies) (*userStatusAdministrationState, error) {
	n := c.UserStatusAdministration
	if n == nil {
		return nil, nil
	}
	repo, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: n.Status.Query.MaximumDuration})
	if err != nil {
		return nil, err
	}
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, audit, outbox})
	if err != nil {
		return nil, err
	}
	keys, err := kernel.NewCoordinatorWithRequestKeys(d.PostgreSQL, registry, c.OTP.Coordinator, c.OTP.RequestKeys)
	if err != nil {
		return nil, err
	}
	uow, err := kernel.NewStatusUnitOfWork(keys, repo, kernel.StatusUnitOfWorkConfig{
		RetentionPolicyVersion: n.RetentionPolicyVersion, PolicyVersion: n.Status.PolicyVersion,
		Policy: n.Status.Policy, Reasons: n.Status.Reasons, MaximumCascadeDuration: n.MaximumCascadeDuration,
		ConsumerContracts: n.ConsumerContracts,
	})
	if err != nil {
		return nil, err
	}
	auth := c.OTP.RequestKeys.Policy.Authorization
	native, err := identity.NewUserStatusService(repo, uow, auth, n.Redact, n.Status)
	if err != nil {
		return nil, err
	}
	ordinary := c.Session.Native
	validation := ordinary.Validation
	validation.Clock = ordinary.Execution.Clock
	login := c.PasswordSignin.Native
	sessions, err := sessionpg.NewMFAPasswordSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{
		Repository: ordinary.Execution.Repository, Profile: login.Profile, Validation: validation,
	})
	if err != nil {
		return nil, err
	}
	status := n.Status
	status.Reasons = slices.Clone(status.Reasons)
	status.Policy.AllowedTransitions = slices.Clone(status.Policy.AllowedTransitions)
	status.Query.RedactionReasons = slices.Clone(status.Query.RedactionReasons)
	return &userStatusAdministrationState{
		native: native, sessions: sessions, keys: keys, preparation: uow, auth: auth, clock: validation.Clock, csrf: login.CSRFKey, status: status,
	}, nil
}

// UserStatusAdministration returns the explicitly selected direct-Go handle.
func (f FeatureSet) UserStatusAdministration() (*UserStatusAdministrationService, error) {
	if f.state == nil {
		return nil, identity.UnavailableError{}
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.closed || f.state.features == nil || !f.state.features.composed || f.state.features.userStatusAdministration == nil {
		return nil, identity.UnavailableError{}
	}
	return &UserStatusAdministrationService{state: f.state}, nil
}

// AdminUserBan commits a keyed status change and pending cleanup. Exact retries
// use the native command journal; no old session is kept usable by the result.
func (s *UserStatusAdministrationService) AdminUserBan(ctx context.Context, req AdminUserStatusRequest) (identity.UserStatusResult, error) {
	return s.change(ctx, adminUserBanAction, req)
}

// AdminUserUnban restores eligibility with a new security epoch. It does not
// return, reenable, or replace pre-ban credentials.
func (s *UserStatusAdministrationService) AdminUserUnban(ctx context.Context, req AdminUserStatusRequest) (identity.UserStatusResult, error) {
	return s.change(ctx, adminUserUnbanAction, req)
}

func (s *UserStatusAdministrationService) change(ctx context.Context, action string, req AdminUserStatusRequest) (result identity.UserStatusResult, err error) {
	if s == nil || s.state == nil {
		return result, identity.UnavailableError{}
	}
	work, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return result, err
	}
	defer done()
	n := s.state.features.userStatusAdministration
	if n == nil {
		return result, identity.UnavailableError{}
	}
	return n.change(work, action, req)
}

func (n *userStatusAdministrationState) change(ctx context.Context, action string, req AdminUserStatusRequest) (result identity.UserStatusResult, err error) {
	defer func() {
		if recover() != nil {
			result, err = identity.UserStatusResult{}, identity.UnavailableError{}
		}
	}()
	work, cancel := context.WithTimeout(ctx, n.status.Query.MaximumDuration)
	defer cancel()
	if err := n.validateRequest(work, action, req); err != nil {
		return result, err
	}
	intent, err := userStatusRequestIntent(req, n.status.PolicyVersion)
	if err != nil {
		return result, err
	}
	observed, actor, err := n.authenticate(work, req)
	if err != nil {
		return result, err
	}
	scope := n.actorScope(action, req, actor)
	if err := n.authorizeTarget(work, scope); err != nil {
		return result, err
	}
	if err := checkAdminStatusFreshness(observed, n.clock.Now()); err != nil {
		return result, err
	}
	keyCaller := scope.Clone()
	keyCaller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}
	key, err := n.keys.ResolveRequestKey(work, kernel.RequestKeyScope{
		TenantID: req.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: action,
	}, req.Key, intent, keyCaller)
	if err != nil {
		return result, err
	}
	if err := checkAdminStatusFreshness(observed, n.clock.Now()); err != nil {
		return result, err
	}
	return n.executeStatus(work, action, req, key.CommandID, scope)
}

func (n *userStatusAdministrationState) actorScope(action string, req AdminUserStatusRequest, actor identity.UserID) authorization.DecisionContext {
	return authorization.DecisionContext{
		PolicyRevision: authorization.Revision(n.status.Query.PolicyVersion),
		Request: authorization.Request{
			Tenant:      authorization.TenantID(req.TenantID),
			Subject:     authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)},
			Action:      authorization.Action(action),
			Resource:    authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(req.UserID)},
			Environment: authorization.Environment{Time: n.status.Query.Clock.Now().UTC()},
		},
	}
}

func (n *userStatusAdministrationState) authorizeTarget(work context.Context, scope authorization.DecisionContext) error {
	admit := scope.Clone()
	admit.Request.Resource.Attributes = authorization.Attributes{
		"identity.command.read-admission": authorization.BoolValue(true),
		"identity.command.recovery":       authorization.BoolValue(false),
	}
	decision, err := n.auth.Decide(work, admit)
	if work.Err() != nil {
		return work.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != scope.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (n *userStatusAdministrationState) executeStatus(work context.Context, action string, req AdminUserStatusRequest, commandID identity.CommandID, scope authorization.DecisionContext) (identity.UserStatusResult, error) {
	// No random command input is generated after this point. The native owner
	// receives exactly the same ID, target, versions and intent on a retry.
	command := identity.UserStatusRequest{
		CommandID: commandID, TenantID: req.TenantID, UserID: req.UserID,
		ExpectedVersion: req.ExpectedVersion, ExpectedAuthorityVersion: req.ExpectedAuthorityVersion,
		Reason: req.Reason, ExpiresAt: req.ExpiresAt, ActorScope: scope,
	}
	if action == adminUserBanAction {
		return n.native.AdminUserBan(work, command)
	}
	return n.native.AdminUserUnban(work, command)
}

func (n *userStatusAdministrationState) validateRequest(ctx context.Context, action string, req AdminUserStatusRequest) error {
	if req.Key == (identity.IdempotencyKey{}) || req.ExpectedVersion == 0 || req.ExpectedVersion == ^uint64(0) ||
		req.ExpectedAuthorityVersion == 0 || req.ExpectedAuthorityVersion == ^uint64(0) ||
		n.status.Query.ValidateCanonicalUserID(ctx, req.UserID) != nil {
		return identity.InvalidInputError{Field: "admin_user_status_request"}
	}
	if action == adminUserBanAction && !slices.Contains(n.status.Reasons, req.Reason) ||
		action == adminUserUnbanAction && (req.Reason != "" || !req.ExpiresAt.IsZero()) {
		return identity.InvalidInputError{Field: "admin_user_status_reason"}
	}
	if expiry := req.ExpiresAt.UTC(); !req.ExpiresAt.IsZero() && (expiry.Year() < 1 || expiry.Year() > 9999 || expiry.Nanosecond()%1000 != 0) {
		return identity.InvalidInputError{Field: "admin_user_status_expiry"}
	}
	return ctx.Err()
}

func userStatusRequestIntent(req AdminUserStatusRequest, statusPolicy uint64) (identity.RequestIntent, error) {
	fields := []identity.FeatureField{
		{Name: "status.tenant", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(req.TenantID)}},
		{Name: "status.target", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(req.UserID)}},
		{Name: "status.aggregate-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: req.ExpectedVersion}},
		{Name: "status.authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: req.ExpectedAuthorityVersion}},
		{Name: "status.policy-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: statusPolicy}},
		{Name: "status.reason", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: req.Reason}},
	}
	if !req.ExpiresAt.IsZero() {
		fields = append(fields, identity.FeatureField{Name: "status.expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: req.ExpiresAt}})
	}
	return identity.NewRequestIntent(fields)
}

func (n *userStatusAdministrationState) authenticate(ctx context.Context, req AdminUserStatusRequest) (session.GetResult, identity.UserID, error) {
	token, err := session.ParseToken(req.Bearer.Token())
	if err != nil {
		return session.GetResult{}, "", identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, "", identity.ForbiddenError{}
	}
	observation, err := n.sessions.Get(ctx, session.GetRequest{TenantID: req.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, "", err
	}
	if err := checkAdminStatusFreshness(observation, n.clock.Now()); err != nil {
		return session.GetResult{}, "", err
	}
	spec, err := observation.Session.Bindings()
	if err != nil || spec.TenantID != req.TenantID {
		return session.GetResult{}, "", identity.ForbiddenError{}
	}
	stored := session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}
	if observation.Session.CSRFState().Check(stored, req.CSRF, n.csrf) != nil {
		return session.GetResult{}, "", identity.ForbiddenError{}
	}
	return observation, spec.UserID, nil
}

func checkAdminStatusFreshness(observation session.GetResult, now time.Time) error {
	if observation.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	factor, err := observation.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" || now.Before(factor.VerifiedAt) || now.Sub(factor.VerifiedAt) >= adminStatusFreshness {
		return identity.ForbiddenError{}
	}
	lifetime, err := observation.Session.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}
