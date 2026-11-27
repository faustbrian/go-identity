package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func proxyBindingFixture(t testing.TB) (*secretenvelope.Service, proxyBindingLocator, proxyOriginalBinding) {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{
		"binding-v1": bytes.Repeat([]byte{1}, 32),
		"binding-v2": bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.PersistentSession, AbsoluteTTL: 37*time.Hour + time.Nanosecond,
		IdleTTL: 71*time.Minute + 3*time.Nanosecond, RefreshAfter: 13*time.Minute + 5*time.Nanosecond,
		FreshFor: 29*time.Minute + 7*time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 27, 12, 0, 0, 123456000, time.UTC)
	l := proxyBindingLocator{
		Tenant: "tenant-a", Transaction: "AgICAgICAgICAgICAgICAg", OriginCommand: "AQEBAQEBAQEBAQEBAQEBAQ",
		CallbackCommand: "AwMDAwMDAwMDAwMDAwMDAw", Production: "production-a", Provider: "oidc-a", ProviderVersion: 7,
		CallbackURI: "https://production.example/oauth/callback", StateKeyVersion: 3,
		LookupDigest: sha256.Sum256([]byte("synthetic-keyed-lookup")), IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
	}
	original := proxyOriginalBinding{
		Evidence: oauth.ProxyOIDCEvidenceBinding{
			TenantID: l.Tenant, TransactionID: l.Transaction, CommandID: l.OriginCommand,
			RequestFingerprint: sha256.Sum256([]byte("synthetic-request")), StateDigest: sha256.Sum256([]byte("synthetic-state")),
			PKCEChallengeDigest:  sha256.Sum256([]byte("synthetic-pkce-challenge")),
			ProductionDeployment: l.Production, PreviewDeployment: "preview-a", ProviderID: l.Provider, ProviderVersion: l.ProviderVersion,
			Issuer: "https://issuer.example", ClientID: "original-private-client", PreviewOrigin: "https://preview.example",
			PreviewRedirect: "https://preview.example/oauth/complete", Recipient: "preview-identity", ClaimsProfile: "claims-a", ClaimsVersion: 11,
			Remember: remember, IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt,
		},
		CallbackNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), GlobalVersion: 13, TenantVersion: 17,
	}
	return service, l, original
}

func TestProxyOriginalBindingRoundTripPreservesOriginalCustody(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		spec, _ := original.Evidence.Remember.Bindings()
		spec.Choice = choice
		if choice == session.BrowserSession {
			spec.AbsoluteTTL = 21*time.Hour + time.Nanosecond
		}
		original.Evidence.Remember, _ = session.NewRememberPolicy(spec)
		wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, original)
		if err != nil || len(wire) == 0 {
			t.Fatal("valid original binding was not sealed", err)
		}
		if _, err := secretenvelope.ParseEnvelope(wire); err != nil {
			t.Fatal("binding is not an upstream secret envelope")
		}
		if bytes.Contains(wire, []byte(original.CallbackNonce)) || bytes.Contains(wire, []byte(original.Evidence.ClientID)) {
			t.Fatal("binding ciphertext disclosed private original data")
		}
		got, err := openProxyOriginalBinding(t.Context(), service, locator, wire)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("binding changed original IDs, evidence, nonce, authority, times or resolved remember policy", err)
		}
		again, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, original)
		if err != nil || bytes.Equal(wire, again) {
			t.Fatal("independent seals must be randomized", err)
		}
		rotated, err := sealProxyOriginalBinding(t.Context(), service, "binding-v2", locator, original)
		if err != nil {
			t.Fatal(err)
		}
		for _, retained := range [][]byte{wire, rotated} {
			got, err := openProxyOriginalBinding(t.Context(), service, locator, retained)
			if err != nil || !reflect.DeepEqual(got, original) {
				t.Fatal("retained rotation changed the original binding", err)
			}
		}
	}
}

func TestProxyOriginalBindingPreservesFullWidthVersions(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	locator.ProviderVersion = math.MaxUint64
	original.Evidence.ProviderVersion = locator.ProviderVersion
	original.GlobalVersion, original.TenantVersion = 1<<63, math.MaxUint64
	wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, original)
	if err != nil {
		t.Fatal("could not seal supported full-width owner versions", err)
	}
	opened, err := openProxyOriginalBinding(t.Context(), service, locator, wire)
	if err != nil || !reflect.DeepEqual(opened, original) {
		t.Fatal("could not authenticate unchanged full-width owner versions", err)
	}
}

func TestProxyOriginalBindingRejectsEveryIndependentRowSubstitution(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, original)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*proxyBindingLocator){
		"tenant":            func(l *proxyBindingLocator) { l.Tenant = "tenant-b" },
		"transaction":       func(l *proxyBindingLocator) { l.Transaction = "BAQEBAQEBAQEBAQEBAQEBA" },
		"origin command":    func(l *proxyBindingLocator) { l.OriginCommand = "BAQEBAQEBAQEBAQEBAQEBA" },
		"callback command":  func(l *proxyBindingLocator) { l.CallbackCommand = "BAQEBAQEBAQEBAQEBAQEBA" },
		"production":        func(l *proxyBindingLocator) { l.Production = "production-b" },
		"provider":          func(l *proxyBindingLocator) { l.Provider = "oidc-b" },
		"provider version":  func(l *proxyBindingLocator) { l.ProviderVersion++ },
		"callback URI":      func(l *proxyBindingLocator) { l.CallbackURI = "https://production.example/other" },
		"state key version": func(l *proxyBindingLocator) { l.StateKeyVersion++ },
		"lookup digest":     func(l *proxyBindingLocator) { l.LookupDigest[0] ^= 1 },
		"issued":            func(l *proxyBindingLocator) { l.IssuedAt = l.IssuedAt.Add(time.Microsecond) },
		"expires":           func(l *proxyBindingLocator) { l.ExpiresAt = l.ExpiresAt.Add(-time.Microsecond) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			wrong := locator
			change(&wrong)
			got, err := openProxyOriginalBinding(t.Context(), service, wrong, wire)
			if err == nil || got != (proxyOriginalBinding{}) {
				t.Fatal("ciphertext accepted a substituted independent row or disclosed original data")
			}
		})
	}
}

func TestProxyOriginalBindingRejectsInvalidOriginalAndLocator(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	changes := map[string]func(*proxyOriginalBinding){
		"zero":                  func(o *proxyOriginalBinding) { *o = proxyOriginalBinding{} },
		"tenant mismatch":       func(o *proxyOriginalBinding) { o.Evidence.TenantID = "tenant-b" },
		"transaction mismatch":  func(o *proxyOriginalBinding) { o.Evidence.TransactionID = "BAQEBAQEBAQEBAQEBAQEBA" },
		"command mismatch":      func(o *proxyOriginalBinding) { o.Evidence.CommandID = "BAQEBAQEBAQEBAQEBAQEBA" },
		"production mismatch":   func(o *proxyOriginalBinding) { o.Evidence.ProductionDeployment = "production-b" },
		"provider mismatch":     func(o *proxyOriginalBinding) { o.Evidence.ProviderID = "oidc-b" },
		"version mismatch":      func(o *proxyOriginalBinding) { o.Evidence.ProviderVersion++ },
		"issued mismatch":       func(o *proxyOriginalBinding) { o.Evidence.IssuedAt = o.Evidence.IssuedAt.Add(time.Microsecond) },
		"expiry mismatch":       func(o *proxyOriginalBinding) { o.Evidence.ExpiresAt = o.Evidence.ExpiresAt.Add(-time.Microsecond) },
		"fingerprint":           func(o *proxyOriginalBinding) { o.Evidence.RequestFingerprint = [32]byte{} },
		"state digest":          func(o *proxyOriginalBinding) { o.Evidence.StateDigest = [32]byte{} },
		"pkce digest":           func(o *proxyOriginalBinding) { o.Evidence.PKCEChallengeDigest = [32]byte{} },
		"same deployment":       func(o *proxyOriginalBinding) { o.Evidence.PreviewDeployment = o.Evidence.ProductionDeployment },
		"invalid deployment":    func(o *proxyOriginalBinding) { o.Evidence.PreviewDeployment = "../preview" },
		"issuer":                func(o *proxyOriginalBinding) { o.Evidence.Issuer = "http://issuer.example" },
		"client":                func(o *proxyOriginalBinding) { o.Evidence.ClientID = "" },
		"preview origin":        func(o *proxyOriginalBinding) { o.Evidence.PreviewOrigin = "https://preview.example/path" },
		"preview host mismatch": func(o *proxyOriginalBinding) { o.Evidence.PreviewRedirect = "https://other.example/complete" },
		"preview alias":         func(o *proxyOriginalBinding) { o.Evidence.PreviewRedirect = "https://preview.example/a/../complete" },
		"recipient":             func(o *proxyOriginalBinding) { o.Evidence.Recipient = "*" },
		"claims profile":        func(o *proxyOriginalBinding) { o.Evidence.ClaimsProfile = "" },
		"claims version":        func(o *proxyOriginalBinding) { o.Evidence.ClaimsVersion = 0 },
		"remember":              func(o *proxyOriginalBinding) { o.Evidence.Remember = session.RememberPolicy{} },
		"nonce":                 func(o *proxyOriginalBinding) { o.CallbackNonce = strings.Repeat("x", 43) },
		"global authority":      func(o *proxyOriginalBinding) { o.GlobalVersion = 0 },
		"tenant authority":      func(o *proxyOriginalBinding) { o.TenantVersion = 0 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			wrong := original
			change(&wrong)
			if wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, wrong); err == nil || len(wire) != 0 {
				t.Fatal("invalid original binding admitted")
			}
		})
	}
	for name, change := range map[string]func(*proxyBindingLocator){
		"zero":                     func(l *proxyBindingLocator) { *l = proxyBindingLocator{} },
		"same command":             func(l *proxyBindingLocator) { l.CallbackCommand = l.OriginCommand },
		"zero state key":           func(l *proxyBindingLocator) { l.StateKeyVersion = 0 },
		"zero lookup":              func(l *proxyBindingLocator) { l.LookupDigest = [32]byte{} },
		"callback":                 func(l *proxyBindingLocator) { l.CallbackURI = "http://production.example/callback" },
		"fractional SQL precision": func(l *proxyBindingLocator) { l.IssuedAt = l.IssuedAt.Add(time.Nanosecond) },
		"not UTC":                  func(l *proxyBindingLocator) { l.IssuedAt = l.IssuedAt.In(time.FixedZone("offset", 3600)) },
		"overlong lifetime":        func(l *proxyBindingLocator) { l.ExpiresAt = l.ExpiresAt.Add(time.Microsecond) },
		"empty lifetime":           func(l *proxyBindingLocator) { l.ExpiresAt = l.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := locator
			change(&wrong)
			matching := original
			matching.Evidence.IssuedAt, matching.Evidence.ExpiresAt = wrong.IssuedAt, wrong.ExpiresAt
			if wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", wrong, matching); err == nil || len(wire) != 0 {
				t.Fatal("invalid independent locator admitted")
			}
		})
	}
}

func TestProxyOriginalBindingRejectsTamperAndNoncanonicalPlaintext(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	wire, err := sealProxyOriginalBinding(t.Context(), service, "binding-v1", locator, original)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(wire)
	bad[len(bad)-1] ^= 1
	for _, malformed := range [][]byte{nil, {1}, bad, wire[:len(wire)-1], bytes.Repeat([]byte{1}, 65537)} {
		if got, err := openProxyOriginalBinding(t.Context(), service, locator, malformed); err == nil || got != (proxyOriginalBinding{}) {
			t.Fatal("tampered or oversized envelope admitted")
		}
	}
	aad, err := proxyBindingAAD(locator, "binding-v1")
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := secretenvelope.ParseEnvelope(wire)
	plain, err := service.Decrypt(t.Context(), secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		append(bytes.Clone(plain), ' '),
		append([]byte(`{"Unknown":true,`), plain[1:]...),
		[]byte(`{}`), []byte(`null`), []byte(`[]`), bytes.Repeat([]byte{' '}, 16385),
	} {
		forged, err := service.Encrypt(t.Context(), secretenvelope.EncryptRequest{Plaintext: malformed, KeyReference: "binding-v1", Context: aad})
		if err != nil {
			t.Fatal(err)
		}
		forgedWire, _ := forged.MarshalBinary()
		if got, err := openProxyOriginalBinding(t.Context(), service, locator, forgedWire); err == nil || got != (proxyOriginalBinding{}) {
			t.Fatal("noncanonical or invalid decrypted binding admitted")
		}
	}
}

func TestProxyOriginalBindingRedactionAndCanceledContext(t *testing.T) {
	service, locator, original := proxyBindingFixture(t)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, original)
		if strings.Contains(text, original.CallbackNonce) || strings.Contains(text, original.Evidence.ClientID) {
			t.Fatal("formatted original disclosed private binding data")
		}
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("accidental JSON persistence of original binding admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if wire, err := sealProxyOriginalBinding(ctx, service, "binding-v1", locator, original); !errors.Is(err, context.Canceled) || len(wire) != 0 {
		t.Fatal("canceled sealing did not fail closed with its context cause")
	}
	for _, invalid := range []struct {
		ctx     context.Context
		service *secretenvelope.Service
		key     string
	}{{nil, service, "binding-v1"}, {t.Context(), nil, "binding-v1"}, {t.Context(), service, ""}, {t.Context(), service, "unavailable"}} {
		if wire, err := sealProxyOriginalBinding(invalid.ctx, invalid.service, invalid.key, locator, original); err == nil || len(wire) != 0 {
			t.Fatal("invalid codec input admitted")
		}
	}
}
