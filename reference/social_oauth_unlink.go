package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

// SocialOAuthUnlinkConfiguration selects native password-authorized account
// unlink. It does not enable an HTTP route or provider revocation.
type SocialOAuthUnlinkConfiguration struct {
	Primary passwordpg.AccountUnlinkPrimaryConfig
	Query   identity.UserQueryConfig
	Redact  identity.RedactFunc
}

func composeSocialOAuthUnlink(c *SocialOAuthConfiguration, social *socialOAuthState, verification *passwordVerificationState) error {
	if c == nil || c.Unlink == nil {
		return nil
	}
	if social == nil || verification == nil || verification.native == nil {
		return identity.InvalidInputError{Field: "reference_social_unlink"}
	}
	cfg := c.Unlink
	primary, err := passwordpg.NewAccountUnlinkPrimarySource(verification.native, cfg.Primary)
	if err != nil {
		return err
	}
	social.unlink, err = oauthpg.NewUnlinkService(social.owner, primary, cfg.Query, cfg.Redact)
	return err
}

// SocialOAuthUnlinkService is the graph-guarded native unlink and recovery
// surface. It neither enlists a provider network actor nor returns tokens.
type SocialOAuthUnlinkService interface {
	Unlink(context.Context, oauthpg.UnlinkRequest) (identity.AccountUnlinkResult, error)
	Recover(context.Context, identity.AccountUnlinkRecoveryRequest) (identity.AccountUnlinkResult, error)
}

// SocialAccountUnlink returns the explicitly configured native service.
// Unselected or closed graphs deny; retrieving a handle performs no IO.
func (f FeatureSet) SocialAccountUnlink() (SocialOAuthUnlinkService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_social_unlink"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.socialOAuth == nil || s.features.socialOAuth.unlink == nil {
		return nil, identity.UnavailableError{}
	}
	return composedSocialUnlink{state: s}, nil
}

type composedSocialUnlink struct{ state *storeState }

func (f composedSocialUnlink) Unlink(ctx context.Context, r oauthpg.UnlinkRequest) (identity.AccountUnlinkResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.Change.TenantID)
	if err != nil {
		return identity.AccountUnlinkResult{}, err
	}
	defer done()
	return f.state.features.socialOAuth.unlink.Unlink(w, r)
}

func (f composedSocialUnlink) Recover(ctx context.Context, r identity.AccountUnlinkRecoveryRequest) (identity.AccountUnlinkResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return identity.AccountUnlinkResult{}, err
	}
	defer done()
	return f.state.features.socialOAuth.unlink.Recover(w, r)
}
