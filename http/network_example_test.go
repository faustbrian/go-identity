package identityhttp_test

import (
	"fmt"
	"net/http/httptest"
	"net/netip"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleNewNetworkResolver() {
	resolver, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits: identityhttp.Limits{
			MaximumHeaderBytes: 8192, MaximumURLBytes: 2048,
			MaximumBodyBytes: 65536, MaximumDecodedBytes: 65536,
			MaximumFields: 100, MaximumDepth: 16,
		},
		MaximumForwardedHops: 8,
		TrustedProxyCIDRs:    []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		TenantHosts:          []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}},
		PublicHosts:          []string{"login.example"},
	})
	if err != nil {
		panic("invalid deployment policy")
	}
	request := httptest.NewRequest("GET", "/resource", nil)
	request.RemoteAddr = "10.0.0.3:1234"
	request.Header.Set("Forwarded", "for=198.51.100.7;host=tenant.example;proto=https")
	facts, err := resolver.Resolve(request)
	if err != nil {
		panic("request denied")
	}
	// Deliberately disclose only selected validated fields, not raw requests.
	fmt.Println(facts.Origin(), facts.Realm() == identityhttp.RealmTenant)
	// Output: https://tenant.example true
}
