package reference

import (
	"context"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
	ssooidc "github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func newEnterpriseOIDCCallbackAdapter(config ssopg.OIDCCallbackAdapterConfig) (ssopg.OIDCParsedCallbackAdapter, error) {
	if config.UseSecrets == nil || config.AcceptTokens == nil {
		return nil, sso.ErrInvalidInput
	}
	return ssooidc.New(ssooidc.Config{
		Transaction:          config.Transaction,
		CredentialGeneration: config.CredentialGeneration,
		Profile:              config.Profile,
		Mapping:              config.Mapping,
		Authorization:        config.Authorization,
		CapabilityExpiresAt:  config.CapabilityExpiresAt,
		Clock:                config.Clock,
		HTTPClient:           config.HTTPClient,
		KeySet:               config.KeySet,
		AdditionalClaims:     config.AdditionalClaims,
		Callback: &ssooidc.CallbackCustody{
			ObservedAt: config.ObservedAt,
			ValidUntil: config.ValidUntil,
			UseSecrets: config.UseSecrets,
			AcceptTokens: func(ctx context.Context, evidence ssooidc.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
				return config.AcceptTokens(ctx, ssopg.OIDCCallbackEvidence{
					Transaction: evidence.Transaction,
					Assertion:   evidence.Assertion,
					Identity:    evidence.Identity,
					ExpiresAt:   evidence.ExpiresAt,
				}, tokens)
			},
		},
	})
}

func newEnterpriseOIDCStartAdapter(config ssopg.OIDCStartAdapterConfig) (sso.ProtocolAdapter, error) {
	return ssooidc.New(ssooidc.Config{
		Transaction:          config.Transaction,
		CredentialGeneration: config.CredentialGeneration,
		Profile:              config.Profile,
		Mapping:              config.Mapping,
		Authorization:        config.Authorization,
		CapabilityExpiresAt:  config.CapabilityExpiresAt,
		Clock:                config.Clock,
	})
}
