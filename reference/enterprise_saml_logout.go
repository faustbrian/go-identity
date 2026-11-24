package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// EnterpriseSAMLLogoutConfiguration opts into retaining the original signed
// subject on new sign-ins and accepting signed logout from one installed IdP.
// ResponseEndpoint is the approved IdP HTTPS POST target, not its entity ID.
// Retain old dedicated match keys while their original sessions can be active.
// Existing sessions without stored correlation are not backfilled.
type EnterpriseSAMLLogoutConfiguration struct {
	IdentityProviderEntityID string
	ResponseEndpoint         string
	CurrentMatchKey          uint32
	MatchKeys                map[uint32][32]byte
}

func (EnterpriseSAMLLogoutConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EnterpriseSAMLLogoutConfiguration(redacted)")
}
func (EnterpriseSAMLLogoutConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (EnterpriseSAMLLogoutConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type enterpriseSAMLLogoutState struct {
	requests         *ssopg.ProviderSAMLIDPLogoutService
	responseEndpoint string
}

func newEnterpriseSAMLLogoutCustody(n EnterpriseSAMLConfiguration, envelopeKeyReference string) (*ssopg.SAMLLogoutSubjectCustody, error) {
	selected := n.Logout
	if selected == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_enterprise_saml_logout"}
	if len(selected.MatchKeys) > 32 || !hasSeparateSAMLStateAndConfirmationKeys(n, selected.MatchKeys) {
		return nil, invalid
	}
	if n.IDPInitiated != nil {
		for _, matchKey := range selected.MatchKeys {
			for _, confirmationKey := range n.IDPInitiated.ConfirmationKeys {
				if matchKey == confirmationKey {
					return nil, invalid
				}
			}
		}
	}
	return ssopg.NewSAMLLogoutSubjectCustody(ssopg.SAMLLogoutSubjectCustodyConfig{
		KeyReference: envelopeKeyReference, CurrentMatchKey: selected.CurrentMatchKey, MatchKeys: selected.MatchKeys,
	})
}

func composeEnterpriseSAMLCompletion(start *ssopg.ProviderLoginService, n EnterpriseSAMLConfiguration, custody *ssopg.SAMLLogoutSubjectCustody) (*ssopg.ProviderSAMLLoginCompletionService, error) {
	if custody == nil {
		n.Completion.Verify = enterpriseSAMLPOSTVerifier(n.ClockSkew)
		return ssopg.NewProviderSAMLLoginCompletionService(start, n.Completion)
	}
	complete, err := ssopg.NewProviderSAMLLoginCompletionServiceWithLogoutSubject(start, n.Completion, enterpriseSAMLPOSTLogoutVerifier(n.ClockSkew))
	if err != nil {
		return nil, err
	}
	return complete.WithLogoutSubjectCustody(custody)
}

func composeEnterpriseSAMLLogout(start *ssopg.ProviderLoginService, n EnterpriseSAMLConfiguration, custody *ssopg.SAMLLogoutSubjectCustody) (*enterpriseSAMLLogoutState, error) {
	selected := n.Logout
	requests, err := ssopg.NewProviderSAMLIDPLogoutService(start, ssopg.ProviderSAMLIDPLogoutConfig{
		Custody: custody,
		Providers: []ssopg.ProviderSAMLIDPLogoutProfile{{
			Provider: n.Profile, IdentityProviderEntityID: selected.IdentityProviderEntityID, ResponseEndpoint: selected.ResponseEndpoint,
		}},
	})
	if err != nil {
		return nil, err
	}
	return &enterpriseSAMLLogoutState{requests: requests, responseEndpoint: selected.ResponseEndpoint}, nil
}
