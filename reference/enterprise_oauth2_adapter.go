package reference

import (
	"context"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
	ssooauth2 "github.com/faustbrian/go-sso/oauth2"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func newEnterpriseOAuth2ProtocolAdapter(config ssopg.OAuth2ProtocolAdapterConfig) (sso.ProtocolAdapter, error) {
	if (config.UseSecrets == nil) != (config.AcceptTokens == nil) {
		return nil, sso.ErrInvalidInput
	}
	var callback *ssooauth2.CallbackCustody
	if config.UseSecrets != nil {
		callback = &ssooauth2.CallbackCustody{
			ObservedAt: config.ObservedAt,
			ValidUntil: config.ValidUntil,
			UseSecrets: config.UseSecrets,
			AcceptTokens: func(ctx context.Context, evidence ssooauth2.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
				return config.AcceptTokens(ctx, ssopg.OAuth2ProtocolEvidence{
					Transaction: evidence.Transaction,
					Assertion:   evidence.Assertion,
					ExpiresAt:   evidence.ExpiresAt,
				}, tokens)
			},
		}
	}
	return ssooauth2.New(ssooauth2.Config{
		Transaction:          config.Transaction,
		CredentialGeneration: config.CredentialGeneration,
		Profile:              config.Profile,
		IdentityProof:        config.IdentityProof,
		Mapping:              config.Mapping,
		Authorization:        config.Authorization,
		CapabilityExpiresAt:  config.CapabilityExpiresAt,
		Clock:                config.Clock,
		HTTPClient:           config.HTTPClient,
		Callback:             callback,
	})
}
