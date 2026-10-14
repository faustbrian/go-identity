package identityhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func networkConfig() identityhttp.NetworkConfig {
	return identityhttp.NetworkConfig{
		Limits: decoderLimits(), MaximumForwardedHops: 8,
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		TenantHosts:       []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}},
		PublicHosts:       []string{"login.example"},
	}
}

func networkRequest(peer, host, forwarded string) *http.Request {
	r := httptest.NewRequest("GET", "/resource", nil)
	r.RemoteAddr, r.Host = peer, host
	if forwarded != "" {
		r.Header.Set("Forwarded", forwarded)
	}
	return r
}

func assertNoNetworkFacts(t *testing.T, facts identityhttp.NetworkFacts, err error) {
	t.Helper()
	if err == nil || facts.Valid() || facts.ClientIP().IsValid() || facts.Host() != "" || facts.Authority() != "" || facts.Scheme() != "" || facts.Realm() != 0 || facts.TenantID() != "" || facts.Forwarded() || facts.Origin() != "" {
		t.Fatal("failure retained usable network facts", err)
	}
}

func TestNetworkMalformedChainDeniesWithoutFallback(t *testing.T) {
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	for _, chain := range []string{
		"", " ", ",", "for=10.0.0.2", "host=tenant.example;proto=https",
		"for=198.51.100.7;host=tenant.example", "for=198.51.100.7;proto=https",
		"for=unknown;host=tenant.example;proto=https", "for=_hidden;host=tenant.example;proto=https",
		"for=198.51.100.7;For=198.51.100.7;host=tenant.example;proto=https",
		"for=198.51.100.7;host=tenant.example;HOST=login.example;proto=https",
		"for=198.51.100.7;host=tenant.example;proto=https;Proto=https",
		"for=198.51.100.7;host=tenant.example;proto=ftp",
		`for="198.51.100.7:_port";host=tenant.example;proto=https`,
		`for="[2001:db8::1%zone]";host=tenant.example;proto=https`,
		`for=2001:db8::1;host=tenant.example;proto=https`,
		`for="198.51.100.7:65536";host=tenant.example;proto=https`,
		`for="[192.0.2.7]";host=tenant.example;proto=https`,
		`for="[2001:db8::1]suffix";host=tenant.example;proto=https`,
		`for="[::]";host=tenant.example;proto=https`,
		`for="[ff02::1]";host=tenant.example;proto=https`,
		`for=198.51.100.7;host="tenant.example:0";proto=https`,
		`for=198.51.100.7;host="tenant.example.";proto=https`,
		`for=198.51.100.7;host="tenant.example;proto=https`,
		`for=198.51.100.7;host=tenant.example;proto=https;by=_hidden`,
		`for =198.51.100.7;host=tenant.example;proto=https`,
		`for= 198.51.100.7;host=tenant.example;proto=https`,
		`for=198.51.100.7;host=tenant.example;proto=https;`,
		`for=198.51.100.7;host=tenant.example;proto=https,`,
		`for=198.51.100.7;host=tenant.example;proto=https,,for=10.0.0.2`,
		// Even an attacker prefix is syntax-checked, never borrowed for authority.
		`for=unknown,for=198.51.100.7;host=tenant.example;proto=https`,
		`for=192.0.2.7;host=tenant.example;proto=https,for=198.51.100.7`,
		`for=192.0.2.7;host=tenant.example;proto=https,for=198.51.100.7;host=tenant.example`,
	} {
		t.Run(chain, func(t *testing.T) {
			facts, err := resolver.Resolve(networkRequest("10.0.0.3:1234", "login.example", chain))
			assertNoNetworkFacts(t, facts, err)
			if !errors.Is(err, identityhttp.ErrUnavailable) {
				t.Fatal("chain failure not unavailable", err)
			}
		})
	}
	for _, headers := range []http.Header{
		{"Forwarded": {"for=198.51.100.7;host=tenant.example;proto=https", "for=10.0.0.2"}},
		{"Forwarded": {"for=198.51.100.7;host=tenant.example;proto=https"}, "forwarded": {"for=10.0.0.2"}},
	} {
		r := networkRequest("10.0.0.3:1234", "login.example", "")
		r.Header = headers
		facts, err := resolver.Resolve(r)
		assertNoNetworkFacts(t, facts, err)
	}
}

func TestNetworkForwardedGrammarAndIPNormalization(t *testing.T) {
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	for _, tc := range []struct{ chain, client string }{
		{`PrOtO=HTTPS;HOST="tenant.example:0443";FoR="[2001:0DB8:0000:0000::7]:65535";by="[2001:db8::2]"`, "2001:db8::7"},
		{`for="[::ffff:198.51.100.7]";host=tenant.example;proto=https`, "198.51.100.7"},
		{`for="198.51.100.8:1";host=tenant.example;proto=https;ext="quoted,semi;slash\\quote\""`, "198.51.100.8"},
		{" \tfor=198.51.100.7 ; host=tenant.example ; proto=https \t,\tfor=10.0.0.2\t", "198.51.100.7"},
	} {
		facts, err := resolver.Resolve(networkRequest("10.0.0.3:1234", "internal.example", tc.chain))
		if err != nil || facts.ClientIP().String() != tc.client || facts.Origin() != "https://tenant.example" || facts.Realm() != identityhttp.RealmTenant {
			t.Fatal("valid closed forwarding syntax failed", err)
		}
	}
}

func TestNetworkHostNormalizationAndExactRealm(t *testing.T) {
	config := networkConfig()
	config.PublicHosts = append(config.PublicHosts, "xn--fa-hia.example", "fass.example", "[2001:db8::1]", "192.0.2.7")
	resolver, err := identityhttp.NewNetworkResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ raw, host, authority string }{
		{"TENANT.example:080", "tenant.example", "tenant.example:80"},
		{"faß.example:8443", "xn--fa-hia.example", "xn--fa-hia.example:8443"},
		{"fass.example", "fass.example", "fass.example"},
		{"LOGIN。example", "login.example", "login.example"},
		{"[2001:0DB8:0:0:0:0:0:1]:80", "[2001:db8::1]", "[2001:db8::1]:80"},
		{"[::ffff:192.0.2.7]", "192.0.2.7", "192.0.2.7"},
		{"192.0.2.7:65535", "192.0.2.7", "192.0.2.7:65535"},
	} {
		facts, err := resolver.Resolve(networkRequest("198.51.100.7:1234", tc.raw, ""))
		if err != nil || facts.Host() != tc.host || facts.Authority() != tc.authority {
			t.Fatal("canonical host/authority mismatch", err)
		}
	}
	for _, host := range []string{
		"", "tenant.example.", "tenant.example.:443", "tenant.example。", "tenant.example。:443",
		"*.tenant.example", "other.tenant.example", "tenant.example.attacker", "user@tenant.example",
		"tenant.example/path", "tenant.example?query", "tenant.example#frag", "tenant%2eexample", " tenant.example",
		"tenant..example", "tenant.example:", "tenant.example:0", "tenant.example:-1", "tenant.example:65536",
		"tenant.example:000080", "tenant.example:port", "[2001:db8::1", "2001:db8::1", "[2001:db8::1]suffix",
		"[192.0.2.7]", "[::]", "[ff02::1]", "[fe80::1%zone]", "127.000.0.1", "0x7f.1", "123",
		"xn--.example", "\xff.example", "a\x00.example", "a\u200d.example", strings.Repeat("a", 64) + ".example",
		strings.Repeat("x", 4097),
	} {
		t.Run(host, func(t *testing.T) {
			facts, err := resolver.Resolve(networkRequest("198.51.100.7:1234", host, ""))
			assertNoNetworkFacts(t, facts, err)
		})
	}
}

func TestNetworkPeerAndProxyPolicy(t *testing.T) {
	config := networkConfig()
	config.TrustedProxyCIDRs = nil
	resolver, _ := identityhttp.NewNetworkResolver(config)
	for _, tc := range []struct{ raw, ip string }{
		{"10.0.0.3:1234", "10.0.0.3"}, {"127.0.0.1:1", "127.0.0.1"},
		{"[2001:0DB8:0:0:0:0:0:7]:65535", "2001:db8::7"},
		{"[fe80::7]:1", "fe80::7"}, {"[::1]:1", "::1"},
	} {
		facts, err := resolver.Resolve(networkRequest(tc.raw, "login.example", "for=unknown"))
		if err != nil || facts.ClientIP().String() != tc.ip || facts.Forwarded() {
			t.Fatal("direct peer failed", err)
		}
	}
	for _, peer := range []string{"", "198.51.100.7", "198.51.100.7:0", "198.51.100.7:65536", "198.51.100.7:port", "host.example:80", "2001:db8::7:80", "[fe80::7%zone]:1", "0.0.0.0:1", "[::]:1", "224.0.0.1:1", "255.255.255.255:1", "[ff02::1]:1", strings.Repeat("x", 129)} {
		facts, err := resolver.Resolve(networkRequest(peer, "login.example", ""))
		assertNoNetworkFacts(t, facts, err)
		if !errors.Is(err, identityhttp.ErrUnavailable) {
			t.Fatal("invalid peer classification", err)
		}
	}
	config.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("2001:db8:1::/48")}
	resolver, err := identityhttp.NewNetworkResolver(config)
	if err != nil {
		t.Fatal("explicit overlapping prefix union rejected", err)
	}
	config.TrustedProxyCIDRs[0] = netip.MustParsePrefix("0.0.0.0/0")
	config.PublicHosts[0] = "attacker.example"
	config.TenantHosts[0].TenantID = "foreign"
	facts, err := resolver.Resolve(networkRequest("11.0.0.1:1", "login.example", "for=unknown"))
	if err != nil || facts.Forwarded() {
		t.Fatal("input mutation changed copied policy", err)
	}
	facts, err = resolver.Resolve(networkRequest("[2001:db8:1::2]:1", "internal.example", "for=198.51.100.7;host=tenant.example;proto=https"))
	if err != nil || !facts.Forwarded() || facts.TenantID() != "tenant-a" {
		t.Fatal("IPv6 prefix or tenant copy failed", err)
	}
}

func TestNetworkMappedZoneCannotDisappearDuringNormalization(t *testing.T) {
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	for i, request := range []*http.Request{
		networkRequest("[::ffff:198.51.100.7%zone]:1", "login.example", ""),
		networkRequest("10.0.0.3:1", "internal.example", `for="[::ffff:198.51.100.7%zone]";host=tenant.example;proto=https`),
		networkRequest("10.0.0.3:1", "internal.example", `for=198.51.100.7;host=tenant.example;proto=https;by="[::ffff:10.0.0.2%zone]"`),
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			facts, err := resolver.Resolve(request)
			assertNoNetworkFacts(t, facts, err)
			if !errors.Is(err, identityhttp.ErrUnavailable) {
				t.Fatal("zone-bearing peer/chain did not fail closed", err)
			}
		})
	}
}

func TestNetworkConstructionBounds(t *testing.T) {
	for _, change := range []func(*identityhttp.NetworkConfig){
		func(c *identityhttp.NetworkConfig) { c.MaximumForwardedHops = 0 },
		func(c *identityhttp.NetworkConfig) { c.MaximumForwardedHops = 17 },
		func(c *identityhttp.NetworkConfig) { c.Limits.MaximumHeaderBytes = 0 },
		func(c *identityhttp.NetworkConfig) { c.TrustedProxyCIDRs = []netip.Prefix{{}} },
		func(c *identityhttp.NetworkConfig) {
			c.TrustedProxyCIDRs = append(c.TrustedProxyCIDRs, c.TrustedProxyCIDRs[0])
		},
		func(c *identityhttp.NetworkConfig) {
			c.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/8")}
		},
		func(c *identityhttp.NetworkConfig) {
			c.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}
		},
		func(c *identityhttp.NetworkConfig) { c.TrustedProxyCIDRs = make([]netip.Prefix, 129) },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = append(c.PublicHosts, "tenant.example") },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = append(c.PublicHosts, "login.example") },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = []string{"LOGIN.example"} },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = []string{"faß.example"} },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = []string{"login.example:80"} },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = nil; c.TenantHosts = nil },
		func(c *identityhttp.NetworkConfig) { c.PublicHosts = make([]string, 1025) },
		func(c *identityhttp.NetworkConfig) { c.TenantHosts[0].TenantID = "" },
		func(c *identityhttp.NetworkConfig) { c.TenantHosts[0].TenantID = "\xff" },
		func(c *identityhttp.NetworkConfig) { c.TenantHosts[0].TenantID = "private\nvalue" },
		func(c *identityhttp.NetworkConfig) { c.TenantHosts[0].TenantID = "private\x7fvalue" },
	} {
		config := networkConfig()
		change(&config)
		resolver, err := identityhttp.NewNetworkResolver(config)
		if resolver != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
}

func TestNetworkForwardedBudgets(t *testing.T) {
	for _, limit := range []uint8{1, 8, 16} {
		config := networkConfig()
		config.MaximumForwardedHops = limit
		resolver, _ := identityhttp.NewNetworkResolver(config)
		for _, count := range []int{int(limit), int(limit) + 1} {
			chain := "for=198.51.100.7;host=tenant.example;proto=https" + strings.Repeat(",for=10.0.0.2", count-1)
			facts, err := resolver.Resolve(networkRequest("10.0.0.3:1234", "internal.example", chain))
			if count == int(limit) {
				if err != nil || !facts.Valid() {
					t.Fatal("exact hop budget rejected", err)
				}
			} else {
				assertNoNetworkFacts(t, facts, err)
			}
		}
	}
	config := networkConfig()
	config.Limits.MaximumHeaderBytes = 1024
	resolver, _ := identityhttp.NewNetworkResolver(config)
	base := `for=198.51.100.7;host=tenant.example;proto=https;ext="`
	// Header accounting: final CRLF + Host + Forwarded field framing.
	const overhead = 2 + 8 + len("internal.example") + len("Forwarded") + 4
	chain := base + strings.Repeat("x", 1024-overhead-len(base)-1) + `"`
	facts, err := resolver.Resolve(networkRequest("10.0.0.3:1", "internal.example", chain))
	if err != nil || !facts.Valid() {
		t.Fatal("exact header budget rejected", err)
	}
	facts, err = resolver.Resolve(networkRequest("10.0.0.3:1", "internal.example", chain+" "))
	assertNoNetworkFacts(t, facts, err)
	for _, count := range []int{16, 17} {
		chain = "for=198.51.100.7;host=tenant.example;proto=https"
		for i := 3; i < count; i++ {
			chain += fmt.Sprintf(";ext%d=value", i)
		}
		facts, err = resolver.Resolve(networkRequest("10.0.0.3:1", "internal.example", chain))
		if count == 16 {
			if err != nil || !facts.Valid() {
				t.Fatal("exact pair budget rejected", err)
			}
		} else {
			assertNoNetworkFacts(t, facts, err)
		}
	}
}

func TestNetworkCancellationIsolationAndRedaction(t *testing.T) {
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	r := networkRequest("198.51.100.7:1", "tenant.example", "")
	facts, err := resolver.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if got := fmt.Sprintf(verb, facts); got != "identityhttp.NetworkFacts(redacted)" {
			t.Fatal("diagnostic leaked", got)
		}
	}
	if got := facts.LogValue().String(); got != "identityhttp.NetworkFacts(redacted)" {
		t.Fatal("structured log leaked", got)
	}
	if _, err := json.Marshal(facts); err == nil {
		t.Fatal("facts serialized")
	}
	if _, err := facts.MarshalText(); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("text serialization accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	zero, err := resolver.Resolve(r.WithContext(ctx))
	assertNoNetworkFacts(t, zero, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	for _, bad := range []*identityhttp.NetworkResolver{nil, {}} {
		zero, err = bad.Resolve(r)
		assertNoNetworkFacts(t, zero, err)
	}
	zero, err = resolver.Resolve(nil)
	assertNoNetworkFacts(t, zero, err)
	var group sync.WaitGroup
	for i := range 32 {
		group.Go(func() {
			host := "login.example"
			if i%2 == 0 {
				host = "tenant.example"
			}
			f, e := resolver.Resolve(networkRequest("198.51.100.7:1", host, ""))
			if e != nil || f.Host() != host || string(f.TenantID()) != map[bool]string{true: "tenant-a", false: ""}[i%2 == 0] {
				t.Error("concurrent request facts crossed", e)
			}
		})
	}
	group.Wait()
}

func FuzzNetworkResolution(f *testing.F) {
	for _, seed := range []string{
		`for=198.51.100.7;host=tenant.example;proto=https`,
		`for="[2001:db8::7]:443";host="tenant.example:443";proto=https`,
		`for=unknown`, `for=198.51.100.7;host="unterminated`,
	} {
		f.Add(seed, "tenant.example", "198.51.100.8:1")
	}
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	f.Fuzz(func(t *testing.T, chain, host, peer string) {
		if len(chain) > 65537 || len(host) > 4097 || len(peer) > 129 {
			t.Skip()
		}
		trusted := networkRequest("10.0.0.3:1", "internal.example", chain)
		facts, err := resolver.Resolve(trusted)
		if err != nil {
			assertNoNetworkFacts(t, facts, err)
		} else if !facts.Valid() || !facts.Forwarded() || facts.Host() != "tenant.example" && facts.Host() != "login.example" {
			t.Fatal("forwarded authority escaped exact map")
		}
		direct := networkRequest(peer, host, chain)
		facts, err = resolver.Resolve(direct)
		if err != nil {
			assertNoNetworkFacts(t, facts, err)
		} else if !facts.Valid() || facts.Host() != "tenant.example" && facts.Host() != "login.example" {
			t.Fatal("direct authority escaped exact map")
		}
	})
}

func TestNetworkTrustedBoundaryTuple(t *testing.T) {
	resolver, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/resource", nil)
	r.RemoteAddr = "10.0.0.3:1234"
	r.Host = "internal.example"
	r.Header.Set("Forwarded", `for=192.0.2.9;host=attacker.example;proto=http, for=198.51.100.7;host="TENANT.example:8443";proto=https, for=10.0.0.2`)
	r.Header.Set("X-Forwarded-For", "192.0.2.9")
	facts, err := resolver.Resolve(r)
	if err != nil || !facts.Valid() || facts.ClientIP().String() != "198.51.100.7" || facts.Host() != "tenant.example" || facts.Authority() != "tenant.example:8443" || facts.Origin() != "https://tenant.example:8443" || facts.Scheme() != "https" || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != "tenant-a" || !facts.Forwarded() {
		t.Fatal("trusted boundary tuple not preserved", err)
	}
}

func TestNetworkDirectIgnoresForwarding(t *testing.T) {
	resolver, _ := identityhttp.NewNetworkResolver(networkConfig())
	r := httptest.NewRequest("GET", "/resource?tenant=foreign", nil)
	r.RemoteAddr = "[::ffff:198.51.100.8]:1234"
	r.Host = "LOGIN.example:443"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Forwarded", `for="unterminated`)
	r.Header.Set("X-Forwarded-Host", "tenant.example")
	facts, err := resolver.Resolve(r)
	if err != nil || !facts.Valid() || facts.ClientIP().String() != "198.51.100.8" || facts.Origin() != "https://login.example" || facts.Realm() != identityhttp.RealmPublic || facts.TenantID() != "" || facts.Forwarded() {
		t.Fatal("untrusted forwarding affected direct facts", err)
	}
	r.Host = "unknown.example"
	facts, err = resolver.Resolve(r)
	var invalid identityhttp.DecodeError
	if !errors.As(err, &invalid) || facts.Valid() {
		t.Fatal("unknown host produced realm authority")
	}
}
