package identityhttp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestOriginExactAdmission(t *testing.T) {
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"},
		RefererFallback: identityhttp.RefererFallbackDeny,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := networkRequest("198.51.100.7:1234", "tenant.example", "")
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://tenant.example")
	if origin, err := guard.Check(r); err != nil || origin != "https://tenant.example" {
		t.Fatal("exact HTTPS origin not admitted", err)
	}
	r.Header.Set("Origin", "https://tenant.example.evil")
	if origin, err := guard.Check(r); err == nil || origin != "" {
		t.Fatal("suffix origin admitted", err)
	}
}

func originGuard(t *testing.T, fallback identityhttp.RefererFallbackPolicy) *identityhttp.OriginGuard {
	t.Helper()
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example", "https://login.example", "https://tenant.example:8443", "https://xn--bcher-kva.example"}, RefererFallback: fallback,
	})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func originRequest(origin string) *http.Request {
	r := networkRequest("198.51.100.7:1234", "tenant.example", "")
	r.TLS = &tls.ConnectionState{}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestOriginMalformedAndUntrusted(t *testing.T) {
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	for _, raw := range []string{
		"null", "https:", "https:tenant.example", "//tenant.example", "http://tenant.example",
		"https://tenant.example.", "https://tenant.example/", "https://tenant.example?",
		"https://tenant.example?q=1", "https://tenant.example#", "https://tenant.example#fragment",
		"https://user@tenant.example", "https://*.example", "https://tenant.example.evil",
		"https://other.tenant.example", "https://tenant.example:0", "https://tenant.example:65536",
		"https://tenant.example:443", "https://tenant.example:0443", "https://TENANT.example",
		"https://tenant.example:8444", " https://tenant.example", "https://tenant.example\t",
		"https://tenant.example,https://login.example", "https://tenant.example https://login.example",
		"https://tenant.example\\@evil.example", "https://tenant%2eexample", "https://bücher.example",
		"chrome-extension://example", "https://2130706433", "https://127.1",
		"https://tenant.example/" + strings.Repeat("a", 2048),
	} {
		t.Run(raw, func(t *testing.T) {
			r := originRequest(raw)
			r.Header.Set("Referer", "https://tenant.example/safe")
			if origin, err := g.Check(r); err == nil || origin != "" {
				t.Fatal("invalid Origin admitted or rescued", err)
			}
		})
	}
	for _, h := range []http.Header{
		{"Origin": {""}}, {"Origin": {}}, {"Origin": {"https://tenant.example", "https://tenant.example"}},
		{"Origin": {"https://tenant.example"}, "origin": {"https://tenant.example"}},
		{"oRiGiN": {""}, "Referer": {"https://tenant.example/path"}},
	} {
		r := originRequest("")
		r.Header = h
		r.Header.Set("Referer", "https://tenant.example/safe")
		if origin, err := g.Check(r); err == nil || origin != "" {
			t.Fatal("ambiguous Origin admitted", err)
		}
	}
	for _, raw := range []string{"https://tenant.example", "https://login.example", "https://tenant.example:8443", "https://xn--bcher-kva.example"} {
		if origin, err := g.Check(originRequest(raw)); err != nil || string(origin) != raw {
			t.Fatal("canonical exact origin denied", err)
		}
	}
}

func TestOriginRefererFallback(t *testing.T) {
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	for _, raw := range []string{"https://tenant.example", "https://tenant.example/path?q=safe", "https://tenant.example:443/path", "https://TENANT.example/path", "https://tenant.example/path,https://evil.example/path"} {
		r := originRequest("")
		r.Header.Set("Referer", raw)
		if origin, err := g.Check(r); err != nil || origin != "https://tenant.example" {
			t.Fatal("same-origin Referer denied", err)
		}
	}
	for _, raw := range []string{
		"", "null", "/path", "//tenant.example/path", "http://tenant.example/path",
		"https://login.example/path", "https://tenant.example:8443/path", "https://user@tenant.example/path",
		"https://tenant.example./path", "https://tenant.example/path#", "https://tenant.example/path#fragment",
		"https://tenant.example/invalid%", "https://tenant.example/path with space", "https://tenant.example\\evil/path",
		"https://tenant.example/" + strings.Repeat("a", 2048),
	} {
		r := originRequest("")
		r.Header.Set("Referer", raw)
		if origin, err := g.Check(r); err == nil || origin != "" {
			t.Fatal("invalid Referer admitted", err)
		}
	}
	for _, headers := range []http.Header{
		{"Referer": {"https://tenant.example/a", "https://tenant.example/b"}},
		{"Referer": {"https://tenant.example/a"}, "referer": {"https://tenant.example/b"}},
	} {
		r := originRequest("")
		r.Header = headers
		if origin, err := g.Check(r); err == nil || origin != "" {
			t.Fatal("ambiguous Referer admitted", err)
		}
	}
	for _, fallback := range []identityhttp.RefererFallbackPolicy{0, identityhttp.RefererFallbackDeny} {
		deny := originGuard(t, fallback)
		r := originRequest("")
		r.Header.Set("Referer", "https://tenant.example/path")
		if origin, err := deny.Check(r); !errors.Is(err, identityhttp.OriginError{}) || origin != "" {
			t.Fatal("default fallback admitted", err)
		}
	}
	// Origin evidence may allow cross-domain browser callers; fallback may not.
	r := originRequest("")
	r.Host = "login.example"
	r.Header.Set("Referer", "https://tenant.example/path")
	if origin, err := g.Check(r); err == nil || origin != "" {
		t.Fatal("different trusted effective origin admitted", err)
	}
	r.Header.Set("Origin", "https://tenant.example")
	if _, err := g.Check(r); err != nil {
		t.Fatal("explicit trusted cross-domain origin denied", err)
	}
}

func TestOriginRefererQueryEscapes(t *testing.T) {
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	for _, tc := range []struct {
		query string
		valid bool
	}{
		{"x=%", false}, {"x=%0", false}, {"x=%gg", false}, {"x=%2g", false},
		{"x=%25", true}, {"x=%2F", true}, {"x=%C3%B6", true}, {"x=hello+world", true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := originRequest("")
			r.Header.Set("Referer", "https://tenant.example/path?"+tc.query)
			origin, err := g.Check(r)
			if tc.valid {
				if err != nil || origin != "https://tenant.example" {
					t.Fatal("valid escaped Referer query denied", err)
				}
			} else if err == nil || origin != "" {
				t.Fatal("malformed Referer query admitted", err)
			}
		})
	}
}

func TestOriginRefererURIGrammar(t *testing.T) {
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	for _, raw := range []string{"|", "^", "`", "{", "}", "<", ">", "\"", "[", "]"} {
		for _, referer := range []string{"https://tenant.example/path" + raw, "https://tenant.example/path?x=" + raw} {
			r := originRequest("")
			r.Header.Set("Referer", referer)
			if origin, err := g.Check(r); err == nil || origin != "" {
				t.Fatal("invalid raw URI character admitted", raw, err)
			}
		}
	}
	for _, referer := range []string{
		"https://tenant.example/path%7C?x=%7C",
		"https://tenant.example/azAZ09-._~!$&'()*+,;=:@/?x=azAZ09-._~!$&'()*+,;=:@/?",
	} {
		r := originRequest("")
		r.Header.Set("Referer", referer)
		if origin, err := g.Check(r); err != nil || origin != "https://tenant.example" {
			t.Fatal("valid URI grammar denied", err)
		}
	}
}

func TestOriginCurrentNetworkAndBinding(t *testing.T) {
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	r := originRequest("")
	r.RemoteAddr, r.Host, r.TLS = "10.0.0.3:1234", "internal.invalid", nil
	r.Header.Set("Forwarded", "for=198.51.100.7;host=tenant.example;proto=https")
	r.Header.Set("Referer", "https://tenant.example/path")
	if _, err := g.CheckBound(r, "https://tenant.example"); err != nil {
		t.Fatal("trusted effective origin denied", err)
	}
	for _, bound := range []identityhttp.Origin{"", "https://login.example", "https://tenant.example:443", "https://unknown.example"} {
		if origin, err := g.CheckBound(r, bound); !errors.Is(err, identityhttp.OriginError{}) || origin != "" {
			t.Fatal("swapped or empty bound origin admitted", err)
		}
	}
	r.RemoteAddr, r.Host = "198.51.100.7:1234", "login.example"
	if origin, err := g.Check(r); err == nil || origin != "" {
		t.Fatal("untrusted Forwarded supplied fallback scheme", err)
	}
	r.TLS = &tls.ConnectionState{}
	if origin, err := g.Check(r); err == nil || origin != "" {
		t.Fatal("untrusted Forwarded supplied fallback host", err)
	}
	r.Header.Set("Referer", "https://login.example/path")
	if origin, err := g.Check(r); err != nil || origin != "https://login.example" {
		t.Fatal("actual effective origin denied", err)
	}
	r.Host = "unknown.example"
	r.Header.Set("Origin", "https://tenant.example")
	if origin, err := g.Check(r); err == nil || origin != "" {
		t.Fatal("trusted origin bypassed unknown host", err)
	}
}

func TestOriginConfigurationOwnershipAndCancellation(t *testing.T) {
	network, _ := identityhttp.NewNetworkResolver(networkConfig())
	for _, config := range []identityhttp.OriginGuardConfig{
		{}, {Network: network}, {Network: &identityhttp.NetworkResolver{}, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}},
		{Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example", "https://tenant.example"}},
		{Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, RefererFallback: 255},
	} {
		if g, err := identityhttp.NewOriginGuard(config); g != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid policy constructed", err)
		}
	}
	for _, raw := range []identityhttp.Origin{"", "http://tenant.example", "null", "https://tenant.example:443", "https://TENANT.example", "https://tenant.example/", "https://tenant.example?", "https://tenant.example#", "https://user@tenant.example"} {
		if g, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{raw}}); g != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("noncanonical policy constructed", err)
		}
	}
	origins := []identityhttp.Origin{"https://tenant.example"}
	g, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: origins})
	if err != nil {
		t.Fatal(err)
	}
	origins[0] = "https://evil.example"
	if _, err := g.Check(originRequest("https://tenant.example")); err != nil {
		t.Fatal("input mutation changed snapshot", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if origin, err := g.Check(originRequest("https://tenant.example").WithContext(ctx)); !errors.Is(err, context.Canceled) || origin != "" {
		t.Fatal("cancellation lost", err)
	}
	for _, owner := range []*identityhttp.OriginGuard{nil, {}} {
		if origin, err := owner.Check(originRequest("https://tenant.example")); !errors.Is(err, identityhttp.ErrInvalidInput) || origin != "" {
			t.Fatal("zero owner admitted", err)
		}
	}
	if origin, err := g.Check(nil); !errors.Is(err, identityhttp.ErrInvalidInput) || origin != "" {
		t.Fatal("nil request admitted", err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				if origin, err := g.CheckBound(originRequest("https://tenant.example"), "https://tenant.example"); err != nil || origin != "https://tenant.example" {
					t.Error("shared immutable guard failed", err)
				}
			}
		})
	}
	wg.Wait()
}

func TestOriginBoundsAndBorrowedRequest(t *testing.T) {
	network, _ := identityhttp.NewNetworkResolver(networkConfig())
	origins := make([]identityhttp.Origin, 129)
	for i := range origins {
		origins[i] = identityhttp.Origin(fmt.Sprintf("https://host%d.example", i))
	}
	if g, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: origins}); g != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("129 origins admitted", err)
	}
	if _, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: origins[:128]}); err != nil {
		t.Fatal("128 origins denied", err)
	}
	g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
	for _, raw := range []string{"https://tenant.example", "https://evil.example"} {
		r := originRequest(raw)
		body := &countedBody{Reader: strings.NewReader("private-body")}
		r.Body = body
		before := r.Header.Clone()
		_, _ = g.Check(r)
		if body.reads != 0 || body.closes != 0 {
			t.Fatal("origin check consumed or closed body")
		}
		if fmt.Sprint(before) != fmt.Sprint(r.Header) || r.Host != "tenant.example" || r.URL.Path != "/resource" {
			t.Fatal("borrowed request mutated")
		}
	}
}

func FuzzOriginAdmission(f *testing.F) {
	for _, raw := range []string{"https://tenant.example", "null", "", "https://tenant.example:443", "https://tenant.example\\@evil.example"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
		r := originRequest("")
		r.Header["Origin"] = []string{raw}
		r.Header.Set("Referer", "https://tenant.example/path")
		origin, err := g.Check(r)
		if err != nil && origin != "" {
			t.Fatal("error retained origin")
		}
		if err == nil && string(origin) != raw {
			t.Fatal("wire origin silently repaired")
		}
	})
}

func FuzzOriginRefererQuery(f *testing.F) {
	for _, query := range []string{"x=%", "x=%0", "x=%gg", "x=%2g", "x=%25", "x=%2F", "x=%C3%B6", "x=hello+world", "x=|", "x=%7C", "x=["} {
		f.Add(query)
	}
	f.Fuzz(func(t *testing.T, query string) {
		g := originGuard(t, identityhttp.RefererFallbackSameOriginHTTPS)
		r := originRequest("")
		r.Header.Set("Referer", "https://tenant.example/path?"+query)
		origin, err := g.Check(r)
		if err != nil {
			if origin != "" {
				t.Fatal("denial retained usable origin")
			}
			return
		}
		if origin != "https://tenant.example" {
			t.Fatal("fallback changed effective origin")
		}
		// Independent lexical oracle: every admitted percent escape must contain
		// exactly two hexadecimal digits; do not call the production URL helper.
		for i := 0; i < len(query); i++ {
			c := query[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/%?", rune(c))) {
				t.Fatal("raw non-URI query character admitted")
			}
			if query[i] != '%' {
				continue
			}
			if i+2 >= len(query) || !strings.ContainsRune("0123456789abcdefABCDEF", rune(query[i+1])) || !strings.ContainsRune("0123456789abcdefABCDEF", rune(query[i+2])) {
				t.Fatal("malformed query percent escape admitted")
			}
			i += 2
		}
	})
}
