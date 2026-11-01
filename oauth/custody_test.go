package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-identity/oauth"
)

func liveProvider(t *testing.T) (*oauth.OIDCProvider, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": esToken(t, key, oidcClaims()), "token_type": "Bearer", "expires_in": 60, "scope": "openid"})
	}))
	t.Cleanup(server.Close)
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	return provider, &calls
}

func TestTokenCustodyBorrowPanicDestroyAndAlias(t *testing.T) {
	provider, _ := liveProvider(t)
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	alias := result.Tokens
	if got := strings.Join(result.Tokens.RequestedScopes(), " "); got != "openid profile" {
		t.Fatal("requested scopes missing")
	}
	if got := strings.Join(result.Tokens.GrantedScopes(), " "); got != "openid" || !result.Tokens.ScopeReported() {
		t.Fatal("provider scope reduction lost")
	}
	requested, granted := result.Tokens.RequestedScopes(), result.Tokens.GrantedScopes()
	requested[0] = "changed"
	granted[0] = "changed"
	if result.Tokens.RequestedScopes()[0] != "openid" || result.Tokens.GrantedScopes()[0] != "openid" {
		t.Fatal("mutable scope projection")
	}
	var borrow oauth.TokenBytes
	err = result.Tokens.Use(context.Background(), func(ctx context.Context, tokens oauth.TokenBytes) error {
		borrow = tokens
		if cap(tokens.AccessToken) != len(tokens.AccessToken) || cap(tokens.RefreshToken) != len(tokens.RefreshToken) || cap(tokens.IDToken) != len(tokens.IDToken) {
			t.Fatal("over-capacity borrow")
		}
		if result.Tokens.Use(ctx, func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
			t.Fatal("reentrant borrow admitted")
		}
		panic("panic-token-secret")
	})
	if err == nil || strings.Contains(fmt.Sprintf("%+v", err), "panic-token-secret") {
		t.Fatal("panic not safely suppressed")
	}
	for _, slice := range [][]byte{borrow.AccessToken, borrow.RefreshToken, borrow.IDToken} {
		for _, b := range slice {
			if b != 0 {
				t.Fatal("panic borrow not cleared")
			}
		}
	}
	sentinel := errors.New("borrow-error-secret")
	err = result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return sentinel })
	if !errors.Is(err, sentinel) || strings.Contains(fmt.Sprintf("%#v", err), "borrow-error-secret") {
		t.Fatal("callback error not classified/redacted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(result.Tokens.Use(ctx, func(context.Context, oauth.TokenBytes) error { return nil }), context.Canceled) {
		t.Fatal("cancelled borrow admitted")
	}
	result.Tokens.Destroy()
	if alias.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
		t.Fatal("alias survived destruction")
	}
}

func TestTokenCustodyConcurrentDestroyDoesNotWaitForBorrower(t *testing.T) {
	provider, _ := liveProvider(t)
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var borrowed []byte
	go func() {
		done <- result.Tokens.Use(ctx, func(ctx context.Context, tokens oauth.TokenBytes) error {
			borrowed = tokens.AccessToken
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("borrow blocked")
	}
	if result.Tokens.Use(ctx, func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
		t.Error("concurrent borrow admitted")
	}
	result.Tokens.Destroy()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("concurrent borrow not cleared")
		}
	}
}

func TestOIDCConcurrentConfigurationUseAndClose(t *testing.T) {
	provider, calls := liveProvider(t)
	const count = 8
	inputs := make([]identity.OAuthCallbackInput, count)
	verifiers := make([]oauth.PKCEVerifier, count)
	for i := range count {
		inputs[i] = callback(t)
		verifiers[i] = verifier(t)
	}
	var group sync.WaitGroup
	failures := make(chan error, count)
	for i := range count {
		group.Go(func() {
			result, err := provider.Exchange(context.Background(), inputs[i], verifiers[i], testNonce)
			defer result.Tokens.Destroy()
			if err != nil {
				failures <- err
			}
			profile := provider.Profile()
			profile.Scopes[0] = "changed"
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if calls.Load() != count {
		t.Fatal("concurrent flow requests lost or repeated")
	}
	provider.Close()
	provider.Close()
	if _, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce); err == nil {
		t.Fatal("closed provider exchanged")
	}
	if _, err := provider.Authorization(context.Background(), oauth.AuthorizationParameters{State: testNonce, Nonce: testNonce, PKCEChallenge: verifier(t).Challenge()}); err == nil {
		t.Fatal("closed provider authorized")
	}
	if calls.Load() != count {
		t.Fatal("closed provider performed network I/O")
	}
}
