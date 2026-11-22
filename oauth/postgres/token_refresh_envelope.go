package postgres

import (
	"context"
	"encoding/binary"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const rpRefreshTokenVaultHeader = "OITV2"
const rpRefreshTokenVaultContext = "identity-oauth-token-vault-refresh-v2"

// V1's actual initial grant is GrantedScopes. Successors retain that authority
// in RequestedScopes, independently of each new access token's GrantedScopes
// (RFC6749 sections 5.1 and 6). The separate schema/context/frame prevents old
// link-token readers from interpreting refresh metadata as initial-link state.
func (s *LinkService) storedProviderRefreshMetadata(p rpPreparedTokenSet) (oauth.ProviderProfile, error) {
	profile, err := s.tokenVaultProfile(p.Binding)
	if err != nil {
		return oauth.ProviderProfile{}, err
	}
	details, ordinary := s.oauth2Profiles[profile.ID]
	facts := oauth.OAuth2UserInfoProfile{Profile: profile, Details: details}
	if !ordinary || s.oauth2TokenPolicies[profile.ID] != "" || facts.ValidateForTokenPolicy("") != nil || p.AccessExpiresAt.IsZero() {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	if p.Version == 1 {
		return s.tokenVaultMetadata(p)
	}
	if p.Schema != 2 || p.Version < 2 || p.SocialConnectionVersion != p.Version || p.Binding.SocialLinkVersion < p.Version || !rpTokenVaultScopes(p.RequestedScopes) || !rpTokenVaultScopes(p.GrantedScopes) || !rpUTCTime(p.ReceivedAt) || !s.tokenVaultExpiry(profile, p.ReceivedAt, p.AccessExpiresAt) || !p.ScopeReported && !slices.Equal(p.RequestedScopes, p.GrantedScopes) {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	for _, scope := range p.RequestedScopes {
		if !slices.Contains(profile.Scopes, scope) {
			return oauth.ProviderProfile{}, identity.ForbiddenError{}
		}
	}
	for _, scope := range p.GrantedScopes {
		if !slices.Contains(p.RequestedScopes, scope) {
			return oauth.ProviderProfile{}, identity.ForbiddenError{}
		}
	}
	return profile, nil
}

func storedProviderRefreshAAD(p rpPreparedTokenSet) (envelope.Context, error) {
	aad, err := rpTokenVaultAAD(p)
	if err != nil || p.Schema == 1 {
		return aad, err
	}
	values := aad.Values()
	values["profile"] = rpRefreshTokenVaultContext
	return envelope.NewContext(values)
}

func storedProviderRefreshScopes(p rpPreparedTokenSet) []string {
	if p.Schema == 1 {
		return p.GrantedScopes
	}
	return p.RequestedScopes
}

// Successful callers own clearing plain; refresh borrows only that allocation.
// Both token slots and the empty ID slot are bounded/authenticated before any
// refresh custody is constructed. Failure and panic erase the entire frame.
func (s *LinkService) openStoredProviderRefreshFrame(ctx context.Context, current rpPreparedTokenSet) (plain, refresh []byte, profile oauth.ProviderProfile, err error) {
	complete := false
	defer func() {
		if !complete {
			clear(plain)
		}
	}()
	profile, err = s.storedProviderRefreshMetadata(current)
	if err != nil {
		return nil, nil, profile, err
	}
	aad, err := storedProviderRefreshAAD(current)
	if err != nil {
		return nil, nil, profile, identity.ForbiddenError{}
	}
	plain, err = s.openRP(ctx, aad, current.Ciphertext, rpMaximumTokenCiphertext)
	if err != nil {
		return nil, nil, profile, rpTokenVaultFailure(ctx, false)
	}
	header := rpTokenVaultHeader
	if current.Schema == 2 {
		header = rpRefreshTokenVaultHeader
	}
	if len(plain) < len(header)+12 || string(plain[:len(header)]) != header {
		return plain, nil, profile, identity.ForbiddenError{}
	}
	remaining := plain[len(header):]
	for i := range 3 {
		if len(remaining) < 4 {
			return plain, nil, profile, identity.ForbiddenError{}
		}
		n := binary.BigEndian.Uint32(remaining)
		remaining = remaining[4:]
		if n > uint32(profile.MaxTokenBytes) || uint64(n) > uint64(len(remaining)) || i < 2 && n == 0 || i == 2 && n != 0 {
			return plain, nil, profile, identity.ForbiddenError{}
		}
		value := remaining[:int(n)]
		for _, b := range value {
			if b < 0x20 || b > 0x7e {
				return plain, nil, profile, identity.ForbiddenError{}
			}
		}
		if i == 1 {
			refresh = value
		}
		remaining = remaining[int(n):]
	}
	if len(remaining) != 0 || ctx.Err() != nil {
		return plain, nil, profile, rpTokenVaultFailure(ctx, false)
	}
	complete = true
	return plain, refresh, profile, nil
}

// Only the admitted native owner receives temporary core refresh custody, never
// plaintext bearer bytes. This does not acquire a lease or authorize provider IO.
func (s *LinkService) openStoredProviderRefresh(ctx context.Context, current rpPreparedTokenSet) (out oauth.RefreshToken, err error) {
	defer func() {
		if recover() != nil {
			out.Destroy()
			out = oauth.RefreshToken{}
			err = rpTokenVaultFailure(ctx, true)
		}
	}()
	if ctx == nil {
		return out, identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	plain, refresh, profile, err := s.openStoredProviderRefreshFrame(ctx, current)
	defer clear(plain)
	if err != nil {
		return out, err
	}
	out, err = oauth.NewRefreshToken(refresh, profile, storedProviderRefreshScopes(current))
	if err != nil {
		return oauth.RefreshToken{}, rpTokenVaultFailure(ctx, false)
	}
	if ctx.Err() != nil {
		out.Destroy()
		return oauth.RefreshToken{}, ctx.Err()
	}
	return out, nil
}

// This consumes all shared result custody, even on preflight failure. A missing
// replacement borrows the authenticated predecessor internally; it is never
// injected into or exposed through the provider's returned TokenSet.
func (s *LinkService) sealStoredProviderRefresh(ctx context.Context, current rpPreparedTokenSet, result oauth.RefreshResult) (out rpPreparedTokenSet, err error) {
	defer result.Tokens.Destroy()
	defer func() {
		if recover() != nil {
			out = rpPreparedTokenSet{}
			err = rpTokenVaultFailure(ctx, true)
		}
	}()
	if ctx == nil {
		return out, identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if current.Version == ^uint64(0) || current.SocialConnectionVersion == ^uint64(0) || current.Binding.SocialLinkVersion == ^uint64(0) {
		return out, identity.ForbiddenError{}
	}
	plain, retainedRefresh, profile, err := s.openStoredProviderRefreshFrame(ctx, current)
	defer clear(plain)
	if err != nil {
		return out, err
	}
	if !slices.Equal(result.Tokens.RequestedScopes(), storedProviderRefreshScopes(current)) {
		return out, identity.ForbiddenError{}
	}
	next := rpPreparedTokenSet{
		Schema: 2, Binding: current.Binding,
		RequestedScopes: result.Tokens.RequestedScopes(), GrantedScopes: result.Tokens.GrantedScopes(), ScopeReported: result.Tokens.ScopeReported(),
		ReceivedAt: result.Tokens.ReceivedAt().UTC(), AccessExpiresAt: result.Tokens.ExpiresAt().UTC(),
		Version: current.Version + 1, SocialConnectionVersion: current.SocialConnectionVersion + 1,
	}
	next.Binding.SocialLinkVersion++
	if _, err := s.storedProviderRefreshMetadata(next); err != nil {
		return out, err
	}
	aad, err := storedProviderRefreshAAD(next)
	if err != nil {
		return out, err
	}
	err = result.Tokens.Use(ctx, func(ctx context.Context, tokens oauth.TokenBytes) error {
		if len(tokens.AccessToken) == 0 || len(tokens.AccessToken) > profile.MaxTokenBytes || len(tokens.IDToken) != 0 || len(tokens.RefreshToken) > profile.MaxTokenBytes {
			return identity.ForbiddenError{}
		}
		refresh := retainedRefresh
		switch result.Rotation {
		case oauth.RotatedRefreshToken:
			if len(tokens.RefreshToken) == 0 {
				return identity.ForbiddenError{}
			}
			refresh = tokens.RefreshToken
		case oauth.RetainOriginalRefreshToken:
			if len(tokens.RefreshToken) != 0 {
				return identity.ForbiddenError{}
			}
		default:
			return identity.ForbiddenError{}
		}
		frame := make([]byte, 0, len(rpRefreshTokenVaultHeader)+12+len(tokens.AccessToken)+len(refresh))
		defer func() { clear(frame) }()
		frame = append(frame, rpRefreshTokenVaultHeader...)
		for _, value := range [][]byte{tokens.AccessToken, refresh, nil} {
			frame = binary.BigEndian.AppendUint32(frame, uint32(len(value)))
			frame = append(frame, value...)
		}
		var sealErr error
		next.Ciphertext, sealErr = s.sealRP(ctx, aad, frame)
		if sealErr != nil {
			return rpTokenVaultFailure(ctx, true)
		}
		if len(next.Ciphertext) == 0 || len(next.Ciphertext) > rpMaximumTokenCiphertext {
			return identity.ForbiddenError{}
		}
		return nil
	})
	if err != nil {
		return out, rpTokenVaultFailure(ctx, true)
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return next, nil
}
