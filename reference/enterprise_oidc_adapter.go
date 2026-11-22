package reference

import (
	"github.com/faustbrian/go-sso"
	ssooidc "github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

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
