package identityhttp_test

import (
	"crypto/tls"
	"fmt"
	"net/http/httptest"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleOriginGuard_CheckBound() {
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 8},
		MaximumForwardedHops: 8, PublicHosts: []string{"login.example"},
	})
	if err != nil {
		panic(err)
	}
	guard, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{"https://login.example"},
		RefererFallback: identityhttp.RefererFallbackDeny,
	})
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest("POST", "/callback", nil)
	r.Host, r.RemoteAddr, r.TLS = "login.example", "198.51.100.7:1234", &tls.ConnectionState{}
	r.Header.Set("Origin", "https://login.example")
	origin, err := guard.CheckBound(r, "https://login.example")
	// Origin admission is only one prerequisite. The owning workflow must still
	// validate its nonce/state/token and atomically consume its continuation.
	fmt.Println(origin, err)
	// Output: https://login.example <nil>
}
