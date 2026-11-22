package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type refreshEnvelopeBoundary interface {
	openStoredProviderRefresh(context.Context, rpPreparedTokenSet) (oauth.RefreshToken, error)
	sealStoredProviderRefresh(context.Context, rpPreparedTokenSet, oauth.RefreshResult) (rpPreparedTokenSet, error)
}

func refreshEnvelopeOwner(t *testing.T, s *LinkService) refreshEnvelopeBoundary {
	t.Helper()
	owner, ok := any(s).(refreshEnvelopeBoundary)
	if !ok {
		t.Fatal("stored provider refresh envelope boundary is not implemented")
	}
	return owner
}

type refreshEnvelopeFixture struct {
	service  *LinkService
	provider *oauth.OAuth2UserInfoProvider
	refresh  *oauth.OAuth2RefreshProvider
	current  rpPreparedTokenSet
	response map[string]any
	status   int
	seen     []string
}

func newRefreshEnvelopeFixture(t *testing.T) *refreshEnvelopeFixture {
	t.Helper()
	f := &refreshEnvelopeFixture{response: map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "expires_in": 60, "scope": "read"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/userinfo" {
			fmt.Fprint(w, `{"id":42}`)
			return
		}
		if r.ParseForm() != nil {
			t.Error("cannot parse token fixture request")
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			f.seen = append(f.seen, r.Form.Get("refresh_token"))
			if f.status != 0 {
				w.WriteHeader(f.status)
			}
			_ = json.NewEncoder(w).Encode(f.response)
			return
		}
		fmt.Fprint(w, `{"access_token":"fixture-initial-access","refresh_token":"fixture-initial-refresh","token_type":"Bearer","expires_in":60,"scope":"write read"}`)
	}))
	t.Cleanup(server.Close)
	provider, err := oauth.NewOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "ordinary", Version: 3, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/userinfo", RedirectURI: "https://app.example/callback",
		ClientID: "client", ClientSecret: []byte("fixture-client-secret"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"read", "write", "admin"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject,
		HTTPClient: server.Client(), Clock: rpVaultClock{time.Date(2026, 11, 22, 0, 0, 0, 123456789, time.UTC)}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	f.provider = provider
	f.refresh, err = oauth.NewOAuth2RefreshProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	profile := provider.OAuth2Profile()
	query := (url.Values{"code": {"fixture-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}).Encode()
	callback, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, profile.Profile.RedirectURI, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	input, ok := callback.Input()
	if !ok {
		t.Fatal("missing parsed callback input")
	}
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	exchanged, err := provider.Exchange(context.Background(), input, verifier, "")
	if err != nil {
		t.Fatal(err)
	}
	service, _, inputTokens := rpVaultFixture(t, true)
	f.service = service
	inputTokens.Destroy()
	f.service.profiles = map[string]oauth.ProviderProfile{profile.Profile.ID: profile.Profile}
	f.service.oauth2Profiles = map[string]oauth.OAuth2UserInfoDetails{profile.Profile.ID: profile.Details}
	binding := rpTokenVaultBinding{TenantID: "tenant-a", UserID: "user-a", AccountID: "account-a", ProviderID: profile.Profile.ID, Issuer: profile.Profile.Issuer, ClientID: profile.Profile.ClientID, ConfigurationVersion: profile.Profile.Version, AccountVersion: 7, SocialLinkVersion: 11}
	f.current, err = f.service.sealProviderTokens(context.Background(), binding, exchanged.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *refreshEnvelopeFixture) result(t *testing.T, current rpPreparedTokenSet) oauth.RefreshResult {
	t.Helper()
	input, err := refreshEnvelopeOwner(t, f.service).openStoredProviderRefresh(context.Background(), current)
	if err != nil {
		t.Fatal("stored refresh restoration failed", err)
	}
	defer input.Destroy()
	result, err := f.refresh.Refresh(context.Background(), input)
	if err != nil {
		t.Fatal("real core refresh failed", err)
	}
	t.Cleanup(result.Tokens.Destroy)
	return result
}

func TestStoredProviderRefreshEnvelopePreservesGrantAcrossSuccessors(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		t.Run(fmt.Sprint("rotation=", rotated), func(t *testing.T) {
			f := newRefreshEnvelopeFixture(t)
			owner := refreshEnvelopeOwner(t, f.service)
			if rotated {
				f.response["refresh_token"] = "fixture-rotated-refresh"
			}
			result := f.result(t, f.current)
			received, expires := result.Tokens.ReceivedAt(), result.Tokens.ExpiresAt()
			next, err := owner.sealStoredProviderRefresh(context.Background(), f.current, result)
			if err != nil {
				t.Fatal("first successor failed", err)
			}
			wantBinding := f.current.Binding
			wantBinding.SocialLinkVersion++
			if next.Schema != 2 || next.Version != 2 || next.SocialConnectionVersion != 2 || next.Binding != wantBinding || !slices.Equal(next.RequestedScopes, []string{"write", "read"}) || !slices.Equal(next.GrantedScopes, []string{"read"}) || !next.ScopeReported || next.ReceivedAt != received || next.AccessExpiresAt != expires {
				t.Fatal("successor lost actual grant, access scope, exact time, or version lineage")
			}
			if result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("seal retained result custody")
			}
			delete(f.response, "scope")
			delete(f.response, "refresh_token")
			secondResult := f.result(t, next)
			last, err := owner.sealStoredProviderRefresh(context.Background(), next, secondResult)
			if err != nil {
				t.Fatal("second successor failed", err)
			}
			if last.Schema != 2 || last.Version != 3 || last.SocialConnectionVersion != 3 || last.Binding.SocialLinkVersion != wantBinding.SocialLinkVersion+1 || last.Binding.AccountVersion != f.current.Binding.AccountVersion || !slices.Equal(last.RequestedScopes, []string{"write", "read"}) || !slices.Equal(last.GrantedScopes, last.RequestedScopes) || last.ScopeReported {
				t.Fatal("narrowed access token redefined refresh authority or omitted-scope metadata")
			}
			wantSecret := "fixture-initial-refresh"
			if rotated {
				wantSecret = "fixture-rotated-refresh"
			}
			if !slices.Equal(f.seen, []string{"fixture-initial-refresh", wantSecret}) {
				t.Fatal("omitted/rotated successor used the wrong retained secret")
			}
			wire, err := json.Marshal(last)
			if err != nil || bytes.Contains(wire, []byte("fixture-")) || strings.Contains(fmt.Sprintf("%#v", last), "fixture-") {
				t.Fatal("stored successor leaked provider bearer data")
			}
			if _, err := f.service.openRP(context.Background(), mustRefreshV1AAD(t, last), last.Ciphertext, rpMaximumTokenCiphertext); err == nil {
				t.Fatal("V2 successor accepted the V1 envelope context")
			}
		})
	}
}

func mustRefreshV1AAD(t *testing.T, p rpPreparedTokenSet) envelope.Context {
	t.Helper()
	aad, err := rpTokenVaultAAD(p)
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func TestStoredProviderRefreshEnvelopeRejectsUnauthenticatedMetadata(t *testing.T) {
	f := newRefreshEnvelopeFixture(t)
	owner := refreshEnvelopeOwner(t, f.service)
	next, err := owner.sealStoredProviderRefresh(context.Background(), f.current, f.result(t, f.current))
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []rpPreparedTokenSet{f.current, next} {
		for name, mutate := range map[string]func(*rpPreparedTokenSet){
			"schema":             func(p *rpPreparedTokenSet) { p.Schema ^= 3 },
			"token version":      func(p *rpPreparedTokenSet) { p.Version++ },
			"connection version": func(p *rpPreparedTokenSet) { p.SocialConnectionVersion++ },
			"account version":    func(p *rpPreparedTokenSet) { p.Binding.AccountVersion++ },
			"social link":        func(p *rpPreparedTokenSet) { p.Binding.SocialLinkVersion++ },
			"tenant":             func(p *rpPreparedTokenSet) { p.Binding.TenantID = "tenant-b" },
			"user":               func(p *rpPreparedTokenSet) { p.Binding.UserID = "user-b" },
			"account":            func(p *rpPreparedTokenSet) { p.Binding.AccountID = "account-b" },
			"client":             func(p *rpPreparedTokenSet) { p.Binding.ClientID = "other" },
			"issuer":             func(p *rpPreparedTokenSet) { p.Binding.Issuer += "/other" },
			"configuration":      func(p *rpPreparedTokenSet) { p.Binding.ConfigurationVersion++ },
			"original grant":     func(p *rpPreparedTokenSet) { p.RequestedScopes = []string{"read"} },
			"access grant":       func(p *rpPreparedTokenSet) { p.GrantedScopes = []string{"admin"} },
			"scope omitted":      func(p *rpPreparedTokenSet) { p.ScopeReported = !p.ScopeReported },
			"received":           func(p *rpPreparedTokenSet) { p.ReceivedAt = p.ReceivedAt.Add(time.Nanosecond) },
			"expiry":             func(p *rpPreparedTokenSet) { p.AccessExpiresAt = p.AccessExpiresAt.Add(time.Second) },
			"ciphertext": func(p *rpPreparedTokenSet) {
				p.Ciphertext = bytes.Clone(p.Ciphertext)
				p.Ciphertext[len(p.Ciphertext)-1] ^= 1
			},
		} {
			t.Run(fmt.Sprintf("v%d/%s", original.Version, name), func(t *testing.T) {
				changed := original
				mutate(&changed)
				input, err := owner.openStoredProviderRefresh(context.Background(), changed)
				input.Destroy()
				if err == nil {
					t.Fatal("unauthenticated grant restored")
				}
			})
		}
	}
}

func TestStoredProviderRefreshEnvelopeChecksResultAuthorityAndConsumesFailures(t *testing.T) {
	for _, fault := range []string{"different grant", "rotation flag", "missing rotation", "zero result", "cancelled", "nil context", "wrong profile", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			f := newRefreshEnvelopeFixture(t)
			owner := refreshEnvelopeOwner(t, f.service)
			result := f.result(t, f.current)
			current := f.current
			ctx := context.Background()
			switch fault {
			case "different grant":
				input, err := oauth.NewRefreshToken([]byte("fixture-other-refresh"), f.provider.Profile(), []string{"read"})
				if err != nil {
					t.Fatal(err)
				}
				defer input.Destroy()
				result.Tokens.Destroy()
				result, err = f.refresh.Refresh(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
			case "rotation flag":
				result.Rotation = oauth.RotatedRefreshToken
			case "missing rotation":
				result.Rotation = ""
			case "zero result":
				result.Tokens.Destroy()
				result = oauth.RefreshResult{}
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "nil context":
				ctx = nil
			case "wrong profile":
				f.service.oauth2Profiles = nil
			case "overflow":
				current.Binding.SocialLinkVersion = ^uint64(0)
			}
			out, err := owner.sealStoredProviderRefresh(ctx, current, result)
			if err == nil || len(out.Ciphertext) != 0 {
				t.Fatal("invalid refresh produced successor custody")
			}
			if fault == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation")
			}
			if result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("failure retained result bearer custody")
			}
		})
	}
}

func TestStoredProviderRefreshEnvelopeRejectsAuthenticatedMalformedFrames(t *testing.T) {
	f := newRefreshEnvelopeFixture(t)
	owner := refreshEnvelopeOwner(t, f.service)
	next, err := owner.sealStoredProviderRefresh(context.Background(), f.current, f.result(t, f.current))
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []rpPreparedTokenSet{f.current, next} {
		aad := mustRefreshV1AAD(t, original)
		if original.Schema == 2 {
			values := aad.Values()
			values["profile"] = "identity-oauth-token-vault-refresh-v2"
			aad, err = envelope.NewContext(values)
			if err != nil {
				t.Fatal(err)
			}
		}
		plain, err := f.service.openRP(context.Background(), aad, original.Ciphertext, rpMaximumTokenCiphertext)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(plain)
		for name, mutate := range map[string]func([]byte) []byte{
			"truncated header":    func(v []byte) []byte { return v[:3] },
			"wrong profile frame": func(v []byte) []byte { v[4] ^= 3; return v },
			"empty access":        func(v []byte) []byte { binary.BigEndian.PutUint32(v[5:], 0); return v },
			"oversized access":    func(v []byte) []byte { binary.BigEndian.PutUint32(v[5:], 16385); return v },
			"empty refresh": func(v []byte) []byte {
				offset := 9 + int(binary.BigEndian.Uint32(v[5:]))
				binary.BigEndian.PutUint32(v[offset:], 0)
				return v
			},
			"unexpected ID token": func(v []byte) []byte { binary.BigEndian.PutUint32(v[len(v)-4:], 1); return append(v, 'a') },
			"truncated body":      func(v []byte) []byte { return v[:len(v)-1] },
			"trailing bytes":      func(v []byte) []byte { return append(v, 1) },
		} {
			t.Run(fmt.Sprintf("v%d/%s", original.Version, name), func(t *testing.T) {
				raw := make([]byte, len(plain), len(plain)+1)
				copy(raw, plain)
				defer clear(raw)
				changedFrame := mutate(raw)
				changed := original
				changed.Ciphertext, err = f.service.sealRP(context.Background(), aad, changedFrame)
				if err != nil {
					t.Fatal(err)
				}
				input, err := owner.openStoredProviderRefresh(context.Background(), changed)
				input.Destroy()
				if err == nil {
					t.Fatal("authenticated malformed refresh frame restored")
				}
			})
		}
	}
}

func TestStoredProviderRefreshEnvelopeRejectsUnsupportedProfilesAndBounds(t *testing.T) {
	for _, fault := range []string{"nil context", "cancelled", "missing details", "changed details", "selected token policy", "absent expiry", "non UTC", "empty ciphertext", "oversized ciphertext"} {
		t.Run(fault, func(t *testing.T) {
			f := newRefreshEnvelopeFixture(t)
			current := f.current
			ctx := context.Background()
			switch fault {
			case "nil context":
				ctx = nil
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "missing details":
				f.service.oauth2Profiles = nil
			case "changed details":
				details := f.service.oauth2Profiles[current.Binding.ProviderID]
				details.UserInfoEndpoint = "https://other.example/userinfo"
				f.service.oauth2Profiles[current.Binding.ProviderID] = details
			case "selected token policy":
				f.service.oauth2TokenPolicies = map[string]oauth.OAuth2TokenPolicy{current.Binding.ProviderID: oauth.OAuth2GitHubOAuthAppPolicy}
			case "absent expiry":
				current.AccessExpiresAt = time.Time{}
			case "non UTC":
				current.ReceivedAt = current.ReceivedAt.In(time.FixedZone("other", 3600))
			case "empty ciphertext":
				current.Ciphertext = nil
			case "oversized ciphertext":
				current.Ciphertext = make([]byte, rpMaximumTokenCiphertext+1)
			}
			input, err := refreshEnvelopeOwner(t, f.service).openStoredProviderRefresh(ctx, current)
			input.Destroy()
			if err == nil {
				t.Fatal("unsupported profile or unbounded encrypted grant restored")
			}
			if fault == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation")
			}
		})
	}
	service, binding, tokens := rpVaultFixture(t, true)
	current, err := service.sealProviderTokens(context.Background(), binding, tokens)
	if err != nil {
		t.Fatal(err)
	}
	input, err := refreshEnvelopeOwner(t, service).openStoredProviderRefresh(context.Background(), current)
	input.Destroy()
	if err == nil {
		t.Fatal("OIDC profile inferred ordinary OAuth2 refresh support")
	}
}
