package postgres

import (
	"reflect"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// Additional protocol facts belong to the existing encrypted RP/configuration
// snapshots. Nil preserves every existing OIDC JSON/AAD byte; this is not another
// replay, discovery, proof or configuration authority.
func oauth2ProviderProfiles(providers []oauth.Provider) (map[string]oauth.OAuth2UserInfoDetails, error) {
	var selected map[string]oauth.OAuth2UserInfoDetails
	for _, provider := range providers {
		facts, ok := provider.(oauth.OAuth2UserInfoFacts)
		if !ok {
			if provider.Profile().ValidateOAuth2Callback() == nil {
				return nil, identity.InvalidInputError{Field: "oauth2_profile"}
			}
			continue
		}
		p := facts.OAuth2Profile()
		if p.Validate() != nil || !reflect.DeepEqual(p.Profile, provider.Profile()) {
			return nil, identity.InvalidInputError{Field: "oauth2_profile"}
		}
		if selected == nil {
			selected = make(map[string]oauth.OAuth2UserInfoDetails)
		}
		selected[provider.ID()] = p.Details
	}
	return selected, nil
}

func oauth2ProfileDetails(profiles map[string]oauth.OAuth2UserInfoDetails, id string) *oauth.OAuth2UserInfoDetails {
	details, ok := profiles[id]
	if !ok {
		return nil
	}
	return &details
}

func oauth2CallbackMatches(callback oauth.Callback, expected *oauth.OAuth2UserInfoDetails) bool {
	details, selected := callback.OAuth2Details()
	if expected == nil {
		return !selected
	}
	return selected && details == *expected
}

func oauth2ProviderMatches(provider oauth.Provider, expected *oauth.OAuth2UserInfoDetails) bool {
	facts, selected := provider.(oauth.OAuth2UserInfoFacts)
	if expected == nil {
		return !selected
	}
	if !selected {
		return false
	}
	profile := facts.OAuth2Profile()
	return profile.Validate() == nil && profile.Details == *expected && reflect.DeepEqual(profile.Profile, provider.Profile())
}

// Existing encrypted RP nonce bytes remain bound/erased as original auxiliary
// state. They are neither sent nor represented as a provider nonce assertion for
// OAuth2. The OIDC argument and all released stored bytes remain unchanged.
func protocolNonce(profile oauth.ProviderProfile, nonce string) string {
	if profile.NonceRequired {
		return nonce
	}
	return ""
}
