package oauth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	oauth "github.com/faustbrian/go-identity/oauth"
)

func ExampleNewOIDCProvider() {
	// This isolated example generates a fixture key. A real configuration supplies
	// the provider's independently authenticated public keys, never a fixture key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("fixture key unavailable")
	}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "example", Version: 1, Issuer: "https://issuer.example",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenEndpoint:         "https://issuer.example/token",
		RedirectURI:           "https://application.example/callback", ClientID: "application",
		ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
		KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
	})
	if err != nil {
		panic("configuration rejected")
	}
	defer provider.Close()
	profile := provider.Profile()
	fmt.Println(profile.ID, profile.Version, profile.ResponseMode, profile.PKCEMethod, profile.NonceRequired)
	// Output: example 1 query S256 true
}
