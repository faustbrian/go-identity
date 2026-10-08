package identityhttp_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func redirectGuard(t testing.TB, targets ...string) *identityhttp.RedirectGuard {
	t.Helper()
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := identityhttp.NewRedirectGuard(identityhttp.RedirectGuardConfig{Network: network, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestRedirectExactBytes(t *testing.T) {
	targets := []string{"https://login.example/callback?a=1&b=%2f", "https://login.example:8443/logout", "https://xn--bcher-kva.example/done", "https://[2001:db8::1]/done"}
	g := redirectGuard(t, targets...)
	targets[0] = "https://evil.example/callback"
	for _, target := range []string{"https://login.example/callback?a=1&b=%2f", targets[1], targets[2], targets[3]} {
		got, err := g.Check(context.Background(), target)
		if err != nil || got != target {
			t.Fatal("registered bytes changed or denied", err)
		}
	}
	for _, target := range []string{
		targets[0], "https://login.example/callback", "https://login.example/callback?b=%2f&a=1",
		"https://login.example/callback?a=1&b=%2F", "https://login.example/callback?a=1&b=/",
		"https://login.example/other?a=1&b=%2f", "https://login.example.evil/callback?a=1&b=%2f",
		"https://LOGIN.example/callback?a=1&b=%2f", "https://login.example:443/callback?a=1&b=%2f",
		"https://login.example/callback?a=1&b=%2f&code=extra", "https://tenant.example/callback?a=1&b=%2f",
	} {
		got, err := g.Check(context.Background(), target)
		var denied identityhttp.OriginError
		if got != "" || !errors.As(err, &denied) || err.Error() != "identity.http.origin_denied" {
			t.Fatal("unregistered redirect admitted or disclosed", err)
		}
	}
}

func TestRedirectConfiguration(t *testing.T) {
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, targets := range [][]string{
		nil, {}, {"https://login.example/done", "https://login.example/done"}, make([]string, 129),
		{""}, {"http://login.example/done"}, {"HTTPS://login.example/done"}, {"//login.example/done"},
		{"https://user@login.example/done"}, {"https://login.example/done#"}, {"https://login.example/done#fragment"},
		{"https://*.example/done"}, {"https://login.example/*"}, {"https://login.example/done?x=*"},
		{"https://login.example\\@evil.example/done"}, {"https://LOGIN.example/done"}, {"https://login.example:443/done"},
		{"https://login.example:0443/done"}, {"https://login.example:0/done"}, {"https://login.example:65536/done"},
		{"https://login.example./done"}, {"https://bücher.example/done"}, {"https://127.1/done"},
		{"https://login.example/done?x=%"}, {"https://login.example/%gg"}, {"https://login.example/a|b"},
		{"https://login.example/done?x=|"}, {"https://login.example/done\r\nLocation:evil"},
		{" https://login.example/done"}, {"https://login.example/" + strings.Repeat("a", 2048)},
	} {
		if g, err := identityhttp.NewRedirectGuard(identityhttp.RedirectGuardConfig{Network: network, Targets: targets}); g != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("unsafe configuration accepted", err)
		}
	}
	for _, owner := range []*identityhttp.NetworkResolver{nil, {}} {
		if g, err := identityhttp.NewRedirectGuard(identityhttp.RedirectGuardConfig{Network: owner, Targets: []string{"https://login.example/done"}}); g != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid owner accepted", err)
		}
	}
	// Both policy cardinality and URL length accept their inclusive upper bound.
	targets := make([]string, 128)
	for i := range targets {
		targets[i] = "https://login.example/" + strings.Repeat("a", i+1)
	}
	g := redirectGuard(t, targets...)
	if got, err := g.Check(context.Background(), targets[127]); err != nil || got != targets[127] {
		t.Fatal("maximum policy denied", err)
	}
	target := "https://login.example/" + strings.Repeat("a", 2048-len("https://login.example/"))
	g = redirectGuard(t, target)
	if got, err := g.Check(context.Background(), target); err != nil || got != target {
		t.Fatal("maximum URL denied", err)
	}
}

func TestRedirectInvalidAndCancelled(t *testing.T) {
	g := redirectGuard(t, "https://login.example/done")
	for _, owner := range []*identityhttp.RedirectGuard{nil, {}} {
		if got, err := owner.Check(context.Background(), "https://login.example/done"); got != "" || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("zero owner admitted", err)
		}
	}
	if got, err := g.Check(nil, "https://login.example/done"); got != "" || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil context admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, target := range []string{"https://login.example/done", "https://evil.example/done"} {
		if got, err := g.Check(ctx, target); got != "" || !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost", err)
		}
	}
	for _, target := range []string{"", "\x00", strings.Repeat("a", 2049)} {
		if got, err := g.Check(context.Background(), target); got != "" || err == nil {
			t.Fatal("invalid target admitted", err)
		}
	}
}

func TestRedirectConcurrentIsolation(t *testing.T) {
	g := redirectGuard(t, "https://login.example/done")
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 32 {
				if got, err := g.Check(context.Background(), "https://login.example/done"); got != "https://login.example/done" || err != nil {
					t.Error("exact target lost", err)
				}
				if got, err := g.Check(context.Background(), "https://login.example/other"); got != "" || err == nil {
					t.Error("cross-request trust leaked", err)
				}
			}
		})
	}
	wg.Wait()
}

func FuzzRedirectExactAdmission(f *testing.F) {
	const target = "https://login.example/callback?a=1&b=%2f"
	for _, seed := range []string{target, "", "https://login.example/callback?b=%2f&a=1", "https://login.example/callback?a=1&b=%2F", "https://evil.example", "https://login.example/callback#", "https://login.example/%", "https://login.example/callback?x=%gg"} {
		f.Add(seed)
	}
	g := redirectGuard(f, target)
	f.Fuzz(func(t *testing.T, candidate string) {
		got, err := g.Check(context.Background(), candidate)
		if candidate == target {
			if got != target || err != nil {
				t.Fatal("registered target denied", err)
			}
		} else if got != "" || err == nil {
			t.Fatal("nonexact target admitted", err)
		}
	})
}
