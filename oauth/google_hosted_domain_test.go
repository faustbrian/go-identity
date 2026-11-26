package oauth_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/oauth"
)

func googleHostedDomainProvider(t *testing.T, key *ecdsa.PrivateKey) (*oauth.OIDCProvider, *atomic.Int32) {
	t.Helper()
	keys := &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	var signatures atomic.Int32
	config := providerConfig(t, "https://token.example/token", nil, key)
	config.Issuer = googleIssuer
	config.KeySet = googleCredentialKeySetFunc(func(ctx context.Context, token string) ([]byte, error) {
		signatures.Add(1)
		return keys.VerifySignature(ctx, token)
	})
	provider, err := oauth.NewGoogleAccountsProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	return provider, &signatures
}

func TestGoogleHostedDomainRequiresSignedClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		value  any
		absent bool
		allow  bool
	}{
		{name: "exact signed domain", value: "example.com", allow: true},
		{name: "missing despite matching verified email", absent: true},
		{name: "null", value: nil},
		{name: "boolean", value: true},
		{name: "number", value: 123},
		{name: "array", value: []string{"example.com"}},
		{name: "object", value: map[string]string{"domain": "example.com"}},
		{name: "empty", value: ""},
		{name: "uppercase", value: "EXAMPLE.COM"},
		{name: "trailing dot", value: "example.com."},
		{name: "leading space", value: " example.com"},
		{name: "trailing newline", value: "example.com\n"},
		{name: "email", value: "user@example.com"},
		{name: "wildcard", value: "*.example.com"},
		{name: "subdomain", value: "other.example.com"},
		{name: "superdomain", value: "com"},
		{name: "suffix attack", value: "example.com.attacker.example"},
		{name: "unicode lookalike", value: "exаmple.com"},
		{name: "over scalar projection limit", value: strings.Repeat("x", 4097)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider, signatures := googleHostedDomainProvider(t, key)
			claims := oidcClaims()
			claims["iss"] = googleIssuer
			claims["email"], claims["email_verified"] = "user@example.com", true
			if !tc.absent {
				claims["hd"] = tc.value
			}
			credential := oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}
			nonce := oauth.GoogleCredentialNonce{OriginalNonce: testNonce}
			got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), credential, nonce, constraint)
			if signatures.Load() != 1 {
				t.Fatal("hosted-domain decision did not use exactly one genuine signature check")
			}
			if tc.allow {
				if err != nil || got.Subject() != claims["sub"] || got.Issuer() != googleIssuer || !got.EvidenceExpiresAt().Equal(testNow.Add(time.Minute)) {
					t.Fatal("matching signed hosted domain lost verified provider evidence", err)
				}
				if when, present := got.AuthenticationTime(); present || !when.IsZero() {
					t.Fatal("hosted-domain verification substituted iat for auth_time")
				}
			} else {
				assertGoogleCredentialFailure(t, got, err, oauth.InvalidProof)
			}
			// Selecting a domain is opt-in. Existing direct verification does not
			// interpret otherwise admissible arbitrary hd claim shapes.
			if ordinary, err := provider.VerifyGoogleCredential(context.Background(), credential, nonce); err != nil || ordinary.Subject() != claims["sub"] {
				t.Fatal("domain selection changed default credential behavior", err)
			}
		})
	}
}

func TestGoogleHostedDomainCanonicalConfiguration(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	for _, domain := range []string{"example.com", "sub.example.com", "example.a1", "xn--bcher-kva.example", "1example.example", longLabel + ".example", longLabel + "." + longLabel + "." + longLabel + "." + strings.Repeat("a", 61)} {
		if _, err := oauth.NewGoogleHostedDomain(domain); err != nil {
			t.Fatal("canonical hosted-domain configuration rejected", err)
		}
	}
	for _, domain := range []string{"", "example", "example.123", "EXAMPLE.COM", "example.com.", ".example.com", "example..com", "-example.com", "example-.com", "exam_ple.com", "*.example.com", "example.com:443", "https://example.com", "user@example.com", " example.com", "example.com\n", "bücher.example", "127.0.0.1", "[::1]", longLabel + "a.example", strings.Repeat("a", 254)} {
		constraint, err := oauth.NewGoogleHostedDomain(domain)
		var rejected *oauth.Error
		if !errors.As(err, &rejected) || rejected.Kind() != oauth.InvalidInput || constraint != (oauth.GoogleHostedDomain{}) {
			t.Fatal("invalid hosted-domain configuration accepted", err)
		}
	}
}

func TestGoogleHostedDomainPreservesGoogleIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{googleIssuer, "accounts.google.com"} {
		provider, signatures := googleHostedDomainProvider(t, key)
		claims := oidcClaims()
		claims["iss"], claims["hd"] = issuer, "example.com"
		claims["auth_time"] = testNow.Add(-time.Minute).Unix()
		claims["email"], claims["email_verified"] = "user@other.example", false
		credential := oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}
		nonce := oauth.GoogleCredentialNonce{OriginalNonce: testNonce}
		got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), credential, nonce, constraint)
		if err != nil || signatures.Load() != 1 {
			t.Fatal("exact signed hd did not pass independently of email", err)
		}
		when, present := got.AuthenticationTime()
		if !present || !when.Equal(testNow.Add(-time.Minute)) || got.Issuer() != googleIssuer || !got.IDTokenIssuedAt().Equal(testNow) || !got.IDTokenExpiresAt().Equal(testNow.Add(time.Minute)) {
			t.Fatal("domain policy changed Google source identity or times")
		}
		ordinary, err := provider.VerifyGoogleCredential(context.Background(), credential, nonce)
		if err != nil || got != ordinary {
			t.Fatal("domain policy retained extra claims or changed opaque identity", err)
		}
	}
}

func googleHostedDomainRawToken(t *testing.T, key *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	message := header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := crypto.SHA256.New()
	_, _ = digest.Write([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestGoogleHostedDomainDuplicateDecodedNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	claims := oidcClaims()
	claims["iss"], claims["hd"] = googleIssuer, "example.com"
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`,"hd":"example.com"`, `,"hd":"attacker.example"`, `,"h\u0064":"example.com"`, `,"\u0068d":"example.com"`, `,"hd":null`} {
		provider, _ := googleHostedDomainProvider(t, key)
		payload := strings.TrimSuffix(string(encoded), "}") + extra + "}"
		credential := oauth.GoogleCredential{IDToken: []byte(googleHostedDomainRawToken(t, key, payload))}
		got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), credential, oauth.GoogleCredentialNonce{OriginalNonce: testNonce}, constraint)
		assertGoogleCredentialFailure(t, got, err, oauth.InvalidProof)
	}
	// One escaped spelling is the same decoded claim, not a duplicate or a
	// differently named claim that may evade exact hd selection.
	provider, _ := googleHostedDomainProvider(t, key)
	payload := strings.Replace(string(encoded), `"hd":`, `"\u0068d":`, 1)
	got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), oauth.GoogleCredential{IDToken: []byte(googleHostedDomainRawToken(t, key, payload))}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce}, constraint)
	if err != nil || got.Subject() != claims["sub"] {
		t.Fatal("single escaped signed hd name was not selected", err)
	}
}

func TestGoogleHostedDomainStillRequiresCompleteProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"iss", "aud", "azp", "sub", "nonce", "iat", "nbf", "exp", "at_hash", "c_hash", "signature"} {
		t.Run(field, func(t *testing.T) {
			provider, _ := googleHostedDomainProvider(t, key)
			claims := oidcClaims()
			claims["iss"], claims["hd"] = googleIssuer, "example.com"
			switch field {
			case "sub":
				claims[field] = ""
			case "iat", "nbf":
				claims[field] = testNow.Add(2 * time.Minute).Unix()
			case "exp":
				claims[field] = testNow.Add(-2 * time.Minute).Unix()
			case "signature":
			default:
				claims[field] = "wrong"
			}
			token := esToken(t, key, claims)
			if field == "signature" {
				token = token[:len(token)-4] + "AAAA"
			}
			got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), oauth.GoogleCredential{IDToken: []byte(token)}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce}, constraint)
			assertGoogleCredentialFailure(t, got, err, oauth.InvalidProof)
		})
	}
}

func TestGoogleHostedDomainPreflightAndRedaction(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, signatures := googleHostedDomainProvider(t, key)
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	claims := oidcClaims()
	claims["iss"], claims["hd"] = googleIssuer, "example.com"
	credential := oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}
	nonce := oauth.GoogleCredentialNonce{OriginalNonce: testNonce}
	got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), credential, nonce, oauth.GoogleHostedDomain{})
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = provider.VerifyGoogleCredentialForHostedDomain(ctx, credential, nonce, constraint)
	assertGoogleCredentialFailure(t, got, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("domain policy lost cancellation cause")
	}
	provider.Close()
	got, err = provider.VerifyGoogleCredentialForHostedDomain(context.Background(), credential, nonce, constraint)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	if signatures.Load() != 0 {
		t.Fatal("invalid local policy or canceled/closed provider reached signature work")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(verb, constraint), "example.com") {
			t.Fatal("hosted-domain configuration disclosed in diagnostics")
		}
	}
	if _, err := json.Marshal(constraint); err == nil {
		t.Fatal("hosted-domain configuration serialized")
	}
}
