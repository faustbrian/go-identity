package reference

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// HTTPUserStatusAdministrationConfiguration selects one or both HTTPS status
// operations over the already-selected direct status owner. Supply exact mapped
// HTTPS origins. When another selected feature owns the shared administrative
// quota, leave AdminNamespace, AdminKey and Denied unset to borrow that quota.
type HTTPUserStatusAdministrationConfiguration struct {
	Ban, Unban     bool
	TrustedOrigins []identityhttp.Origin
	AdminNamespace string
	AdminKey       [32]byte
	Denied         func(context.Context, organizationhttp.AdminRateEvent) error
}

func (HTTPUserStatusAdministrationConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPUserStatusAdministrationConfiguration(redacted)"))
}

func (HTTPUserStatusAdministrationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (HTTPUserStatusAdministrationConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type userStatusHTTPState struct {
	ban, unban bool
	origins    []identityhttp.Origin
	cookie     string
	admin      *organizationhttp.AdminRateLimiter
	ownsAdmin  bool
}

func (n *userStatusAdministrationState) closeHTTP() {
	if n != nil && n.http != nil && n.http.ownsAdmin {
		n.http.admin.Close()
	}
}

func composeUserStatusHTTP(c StoreConfiguration, n *userStatusAdministrationState, rate *httpRateState, org *organizationHTTPState, directory *directorySyncState, scim *managedSCIMCreateState, impersonation *impersonationState) error {
	h := c.HTTPUserStatusAdministration
	if h == nil {
		return nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_user_status"}
	if n == nil || n.http != nil || c.PasswordSignin == nil || c.HTTPRate == nil || rate == nil {
		return invalid
	}
	cookie, err := c.PasswordSignin.Native.Issuance.Cookie.DeletionAttributes()
	if err != nil {
		return invalid
	}
	selected := &userStatusHTTPState{ban: h.Ban, unban: h.Unban, origins: slices.Clone(h.TrustedOrigins), cookie: cookie.Name}
	var candidates [4]*organizationhttp.AdminRateLimiter
	if org != nil {
		candidates[0] = org.admin
	}
	if directory != nil {
		candidates[1] = directory.admin
	}
	if scim != nil {
		candidates[2] = scim.rate
	}
	if impersonation != nil {
		candidates[3] = impersonation.admin
	}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if !candidate.Configured() || selected.admin != nil && selected.admin != candidate {
			return invalid
		}
		selected.admin = candidate
	}
	if selected.admin != nil {
		if h.AdminNamespace != "" || h.AdminKey != ([32]byte{}) || h.Denied != nil {
			return invalid
		}
	} else {
		selected.admin, err = organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{
			Shared: rate.backend, Namespace: h.AdminNamespace, Key: h.AdminKey, Denied: h.Denied,
			Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration,
		})
		if err != nil {
			return invalid
		}
		selected.ownsAdmin = true
	}
	n.http = selected
	return nil
}

func (s *Server) userStatusFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	n := s.state.features.userStatusAdministration
	if n == nil || n.http == nil {
		return nil, nil
	}
	h := n.http
	feature, err := sessionhttp.NewAdminUserStatusFeature(sessionhttp.AdminUserStatusConfig{
		Ban: h.ban, Unban: h.unban, Network: network, TrustedOrigins: h.origins, OriginalCookieName: h.cookie,
		Native: httpUserStatusOwner{state: s.state}, Rate: h.admin, MaximumDuration: n.status.Query.MaximumDuration,
	})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

type httpUserStatusOwner struct{ state *storeState }

func (s httpUserStatusOwner) BanUserWithAdmission(ctx context.Context, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error) (identity.UserStatusResult, error) {
	return s.change(ctx, adminUserBanAction, input, admit)
}

func (s httpUserStatusOwner) UnbanUserWithAdmission(ctx context.Context, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error) (identity.UserStatusResult, error) {
	return s.change(ctx, adminUserUnbanAction, input, admit)
}

func (s httpUserStatusOwner) change(ctx context.Context, action string, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error) (result identity.UserStatusResult, err error) {
	defer func() {
		if recover() != nil {
			result, err = identity.UserStatusResult{}, identity.UnavailableError{}
		}
	}()
	request, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return result, err
	}
	defer done()
	n := s.state.features.userStatusAdministration
	if n == nil || n.http == nil || n.preparation == nil || admit == nil ||
		action == adminUserBanAction && !n.http.ban || action == adminUserUnbanAction && !n.http.unban {
		return result, identity.UnavailableError{}
	}
	work, cancel := context.WithTimeout(request, n.status.Query.MaximumDuration)
	defer cancel()
	if n.status.Query.ValidateCanonicalUserID(work, input.UserID) != nil {
		return result, identity.InvalidInputError{Field: "user_id"}
	}
	req := AdminUserStatusRequest{TenantID: input.TenantID, Bearer: input.Bearer, CSRF: input.CSRF, Key: input.Key,
		UserID: input.UserID, Reason: input.Reason, ExpiresAt: input.ExpiresAt}
	observed, actor, err := n.authenticate(work, req)
	if err != nil {
		return result, err
	}
	work, expire := context.WithTimeout(work, observed.ValidUntil().Sub(n.clock.Now()))
	defer expire()
	scope := n.actorScope(action, req, actor)
	if err := n.authorizeTarget(work, scope); err != nil {
		return result, err
	}
	if err := checkAdminStatusFreshness(observed, n.clock.Now()); err != nil {
		return result, err
	}
	if err := admit(work, actor); err != nil {
		return result, err
	}
	if err := checkAdminStatusFreshness(observed, n.clock.Now()); err != nil {
		return result, err
	}
	prepared, err := n.preparation.ResolveAdminStatusKey(work, req.Key, kernel.AdminStatusKeyRequest{
		UserID: req.UserID, ExpectedVersion: input.ExpectedVersion, Reason: req.Reason, ExpiresAt: req.ExpiresAt,
	}, scope)
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) && unknown.CommandID != "" {
			result.CommandID, result.CommitOutcome = unknown.CommandID, identity.CommitOutcomeUnknown
		}
		return result, err
	}
	if err := checkAdminStatusFreshness(observed, n.clock.Now()); err != nil {
		return result, err
	}
	req.ExpectedVersion, req.ExpectedAuthorityVersion = prepared.ExpectedVersion, prepared.ExpectedAuthorityVersion
	return n.executeStatus(work, action, req, prepared.CommandID, scope)
}
