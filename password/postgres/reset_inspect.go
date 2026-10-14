package passwordpostgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
)

var _ password.ResetInspectionService = (*ResetService)(nil)

// ResetInspect observes original unused issuance and current email-recovery
// eligibility without reservation, consumption, hashing, delivery or session
// effects. Invalid/used/stale/foreign proofs yield only Valid=false; unavailable
// owners and cancellation return no positive result. The proof and primary pool
// remain borrowed, and earlier deadlines win. Concurrent-safe inspection is an
// advisory observation, never authorization held across a later completion.
func (s *ResetService) ResetInspect(ctx context.Context, r password.ResetInspectRequest) (out password.ResetInspectResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.issuer == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = password.ResetInspectResult{}
		}
	}()
	invalid := func(e error) (password.ResetInspectResult, error) {
		var denied identity.ForbiddenError
		if errors.As(e, &denied) || errors.Is(e, identity.ErrUserAbsent) || errors.Is(e, password.ErrInvalidReset) || errors.Is(e, password.ErrCredentialAbsent) {
			return password.ResetInspectResult{}, nil
		}
		return password.ResetInspectResult{}, e
	}
	if !slices.Contains(c.Origins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	grant, original, _, err := s.issuer.ValidateIssuedProof(ctx, s.pool, r.Token, "identity.password.reset-complete")
	if err != nil {
		return invalid(err)
	}
	now := c.Coordinator.QueryPolicy.Clock.Now()
	origin, err := s.profile.ResolveOriginal(grant, now)
	if err != nil || origin.TenantID != r.TenantID || origin.OriginCommandID != original || origin.FactorVersion == 0 {
		return out, nil
	}
	caller := r.Caller.Clone()
	if caller.Request.Resource.ID != "" && caller.Request.Resource.ID != authorization.ResourceID(origin.UserID) {
		return out, nil
	}
	caller.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	phase := &resetCompletionPhase{origin: origin}
	if err := s.selectResetCompletion(ctx, phase, caller); err != nil {
		return invalid(err)
	}
	material, err := s.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: origin.TenantID, SubjectID: origin.UserID})
	if err != nil {
		return invalid(err)
	}
	authority := material.Authority()
	if identity.CheckPasswordRecoveryAuthority(authority, authority.Credential, origin.CredentialAuthorityVersion, authority.Enabled, now) != nil || authority.Credential.ID != origin.CredentialID || authority.Credential.Version != origin.CredentialVersion {
		return out, nil
	}
	version, active, err := mfapg.ReadPasswordSigninFactors(ctx, s.pool, origin.TenantID, origin.UserID, min(c.Repository.MaximumDuration, 5*time.Second))
	if err != nil {
		return invalid(err)
	}
	if active || version != origin.FactorVersion {
		return out, nil
	}
	// An intervening reservation/consumption must not become a positive UI
	// result after current-owner reads. This still grants no future clearance.
	if _, _, _, err := s.issuer.ValidateIssuedProof(ctx, s.pool, r.Token, "identity.password.reset-complete"); err != nil {
		return invalid(err)
	}
	return password.ResetInspectResult{Valid: true}, nil
}
