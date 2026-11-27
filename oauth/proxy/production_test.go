package oauthproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func TestProductionCallbackLookupDoesNotReserveOrExchange(t *testing.T) {
	f := newCallbackFixture(t)
	p, err := newProductionCallback(ProductionCallbackConfig{ProductionDeployment: "production-a",
		Codec: f.codec, Store: f.store, Clock: f.clock, Targets: []PreviewTarget{f.target}}, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []bool{false, true} {
		query := f.query
		if denied {
			query = strings.Replace(query, "code=local-code", "error=access_denied", 1)
		}
		got, err := p.Lookup(t.Context(), f.route, query)
		if err != nil || got.StateDigest != sha256.Sum256([]byte(f.state)) || got.ProviderDenied != denied ||
			got.ProviderID != f.provider.profile.ID || got.ProviderVersion != f.provider.profile.Version || got.Issuer != f.provider.profile.Issuer ||
			got.ClientID != f.provider.profile.ClientID || got.ProductionDeployment != "production-a" || got.ProductionCallback != f.route {
			t.Fatal("lookup did not preserve exact configured query attribution", err)
		}
	}
	for _, invalid := range []struct{ route, query string }{{f.route + "/other", f.query}, {f.route, f.query + "&state=duplicate"}} {
		if got, err := p.Lookup(t.Context(), invalid.route, invalid.query); !errors.Is(err, CallbackInvalid) || got != (CallbackLookup{}) {
			t.Fatal("invalid callback disclosed attribution", err)
		}
	}
	if f.store.reserved != 0 || f.provider.attempts != 0 || f.store.terminal != 0 {
		t.Fatal("transport lookup acted as native authority")
	}
}

func TestProductionCallbackGatesProviderWorkOnOriginalReservation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alter    func(*callbackFixture)
		want     CallbackError
		reserved int
		attempts int
		terminal CallbackDisposition
	}{
		{"unregistered production callback", func(f *callbackFixture) { f.route += "/alternate" }, CallbackInvalid, 0, 0, 0},
		{"malformed provider callback", func(f *callbackFixture) { f.query += "&state=duplicate" }, CallbackInvalid, 0, 0, 0},
		{"unknown reserve acknowledgement", func(f *callbackFixture) { f.store.reserveErr = errors.New("sensitive driver details") }, CallbackReconcile, 1, 0, 0},
		{"already reserved original", func(f *callbackFixture) { f.store.reserveErr = ErrOriginalUnavailable }, CallbackDenied, 1, 0, 0},
		{"wrong state in reserved record", func(f *callbackFixture) { f.store.original.Binding.StateDigest[0] ^= 1 }, CallbackReconcile, 1, 0, CallbackNeedsReconciliation},
		{"wrong PKCE for reserved state", func(f *callbackFixture) { f.store.original.Binding.PKCEChallengeDigest[0] ^= 1 }, CallbackReconcile, 1, 0, CallbackNeedsReconciliation},
		{"other provider version", func(f *callbackFixture) { f.store.original.Binding.ProviderVersion++ }, CallbackReconcile, 1, 0, CallbackNeedsReconciliation},
		{"unregistered preview path", func(f *callbackFixture) { f.store.original.Binding.PreviewRedirect += "/other" }, CallbackReconcile, 1, 0, CallbackNeedsReconciliation},
		{"expired original", func(f *callbackFixture) { f.store.original.Binding.ExpiresAt = f.now }, CallbackDenied, 1, 0, CallbackRejected},
		{"provider denial without revealing PKCE", func(f *callbackFixture) {
			f.query = strings.Replace(f.query, "code=local-code", "error=access_denied", 1)
			f.store.original.Verifier = oauth.PKCEVerifier{}
			f.store.original.Nonce = ""
		}, CallbackDenied, 1, 0, CallbackRejected},
		{"ambiguous exchange", func(*callbackFixture) {}, CallbackReconcile, 1, 1, CallbackNeedsReconciliation},
		{"failed terminal acknowledgement", func(f *callbackFixture) { f.store.finishErr = errors.New("sensitive terminal details") }, CallbackReconcile, 1, 1, CallbackNeedsReconciliation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			tc.alter(&fixture)
			callback, err := newProductionCallback(ProductionCallbackConfig{
				ProductionDeployment: "production-a", Codec: fixture.codec,
				Store: fixture.store, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
			}, fixture.provider)
			if err != nil {
				t.Fatal(err)
			}
			result, err := callback.Handle(t.Context(), fixture.route, fixture.query)
			if !errors.Is(err, tc.want) || result.Destination() != "" || len(result.Envelope()) != 0 {
				t.Fatalf("failure returned a handoff or wrong disposition: %v", err)
			}
			if fixture.store.reserved != tc.reserved || fixture.provider.attempts != tc.attempts || fixture.store.terminal != tc.terminal {
				t.Fatalf("unexpected effects: reserved %d attempts %d terminal %v", fixture.store.reserved, fixture.provider.attempts, fixture.store.terminal)
			}
			if tc.reserved > 0 && fixture.store.selected.StateDigest != sha256.Sum256([]byte(fixture.state)) {
				t.Fatal("lookup did not use the digest of the presented original state")
			}
			if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "local-code") {
				t.Fatal("callback exposed collaborator or callback custody")
			}
		})
	}
}

func TestProductionCallbackSettlesAmbiguousExchangeAfterCancellation(t *testing.T) {
	fixture := newCallbackFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.provider.onExchange = cancel
	callback, err := newProductionCallback(ProductionCallbackConfig{
		ProductionDeployment: "production-a", Codec: fixture.codec,
		Store: fixture.store, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
	}, fixture.provider)
	if err != nil {
		t.Fatal(err)
	}
	result, err := callback.Handle(ctx, fixture.route, fixture.query)
	if !errors.Is(err, CallbackReconcile) || result.Destination() != "" || len(result.Envelope()) != 0 {
		t.Fatalf("cancellation exposed a handoff or hid ambiguous exchange: %v", err)
	}
	if fixture.store.terminal != CallbackNeedsReconciliation || fixture.store.finishContextErr != nil || !fixture.store.finishHasDeadline {
		t.Fatal("ambiguous reserved work did not reach bounded independent settlement")
	}
	if fixture.store.original.Verifier.Challenge() != "" {
		t.Fatal("callback retained borrowed verifier custody after cancellation")
	}
}

type callbackFixture struct {
	now                 time.Time
	route, state, query string
	clock               fixtureClock
	provider            *callbackProvider
	store               *callbackStore
	codec               *oauth.ProxyOIDCEvidenceCodec
	target              PreviewTarget
}

func newCallbackFixture(t *testing.T) callbackFixture {
	t.Helper()
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	clock := fixtureClock{now}
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	profile := oauth.ProviderProfile{
		ID: "oidc", Version: 2, Issuer: "https://issuer.example", ClientID: "client-a",
		AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token",
		RedirectURI: "https://production.example/oauth/provider/callback", ClientAuthentication: oauth.PublicClient,
		Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, NonceRequired: true, NonceBytes: 32,
		StateBytes: 32, ResponseMode: "query", PKCEMethod: "S256", Timeout: time.Second, ClockSkew: time.Minute,
		MaxResponseBytes: 8192, MaxTokenBytes: 4096, MaxCodeBytes: 2048,
	}
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("x", 43)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.Destroy)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: 8 * time.Hour,
		IdleTTL: time.Hour, RefreshAfter: 10 * time.Minute, FreshFor: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := PreviewTarget{Deployment: "preview-a", Origin: "https://preview.example", Redirect: "https://preview.example/complete", Recipient: "test-preview"}
	binding := oauth.ProxyOIDCEvidenceBinding{
		TenantID: "tenant-a", CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TransactionID: "AgICAgICAgICAgICAgICAg",
		RequestFingerprint: sha256.Sum256([]byte("original")), StateDigest: sha256.Sum256([]byte(state)),
		PKCEChallengeDigest: sha256.Sum256([]byte(verifier.Challenge())), ProductionDeployment: "production-a",
		PreviewDeployment: target.Deployment, PreviewOrigin: target.Origin, PreviewRedirect: target.Redirect, Recipient: target.Recipient,
		ProviderID: profile.ID, ProviderVersion: profile.Version, Issuer: profile.Issuer, ClientID: profile.ClientID,
		ClaimsProfile: "minimum", ClaimsVersion: 1, Remember: remember, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}
	store := &callbackStore{original: OriginalCallback{ID: sha256.Sum256([]byte("reservation")), Binding: binding, Verifier: verifier, Nonce: state}}
	return callbackFixture{
		now: now, clock: clock, state: state, route: profile.RedirectURI,
		query:    url.Values{"state": {state}, "code": {"local-code"}, "iss": {profile.Issuer}}.Encode(),
		provider: &callbackProvider{profile: profile, store: store}, store: store,
		codec: &oauth.ProxyOIDCEvidenceCodec{}, target: target,
	}
}

type fixtureClock struct{ now time.Time }

func (c fixtureClock) Now() time.Time { return c.now }

type callbackProvider struct {
	profile    oauth.ProviderProfile
	store      *callbackStore
	attempts   int
	onExchange func()
}

func (p *callbackProvider) Profile() oauth.ProviderProfile { return p.profile }

func (p *callbackProvider) Exchange(context.Context, identity.OAuthCallbackInput, oauth.PKCEVerifier, string) (oauth.ProviderIdentity, error) {
	if p.store.reserved != 1 || p.store.reserveErr != nil {
		panic("provider entered without acknowledged reservation")
	}
	p.attempts++
	if p.onExchange != nil {
		p.onExchange()
	}
	return oauth.ProviderIdentity{}, errors.New("sensitive provider details")
}

type callbackStore struct {
	original                                OriginalCallback
	reserveErr, finishErr, finishContextErr error
	reserved                                int
	selected                                CallbackLookup
	terminal                                CallbackDisposition
	finishHasDeadline                       bool
	checkForward                            func() bool
	envelope                                []byte
}

func (s *callbackStore) Reserve(_ context.Context, lookup CallbackLookup) (OriginalCallback, error) {
	s.reserved++
	s.selected = lookup
	if s.reserveErr != nil {
		return OriginalCallback{}, s.reserveErr
	}
	return s.original, nil
}

func (s *callbackStore) Finalize(ctx context.Context, id [32]byte, terminal CallbackDisposition, envelope []byte) error {
	if id != s.original.ID || terminal != CallbackForwarded && len(envelope) != 0 {
		panic("unexpected failure finalization")
	}
	if terminal == CallbackForwarded {
		if len(envelope) == 0 || s.checkForward == nil || !s.checkForward() {
			panic("forwarding before provider disposal acknowledgement")
		}
		s.envelope = bytes.Clone(envelope)
	}
	s.terminal = terminal
	s.finishContextErr = ctx.Err()
	_, s.finishHasDeadline = ctx.Deadline()
	return s.finishErr
}
