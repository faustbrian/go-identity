package passwordpostgres

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

func TestNativeSigninSigningKeyOwnsOriginalRecord(t *testing.T) {
	material := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	public := bytes.Clone(material[ed25519.SeedSize:])
	key, err := NewSigninSigningKey("signin-1", material)
	if err != nil {
		t.Fatal(err)
	}
	clear(material)
	original := originalSigninFixture(t)
	got, err := key.sign(original)
	frame, frameErr := got.SigningBytes()
	if err != nil || frameErr != nil || got.KeyID != "signin-1" || !ed25519.Verify(public, frame, got.Signature) || original.KeyID != "evidence-1" || !got.Proof.IssuedAt.Equal(original.Proof.IssuedAt) || got.CredentialVersion != original.CredentialVersion {
		t.Fatal("original native signing custody lost")
	}
	id, exported := key.public()
	if id != "signin-1" || !bytes.Equal(public, exported) {
		t.Fatal("retained public key")
	}
	clear(exported)
	_, again := key.public()
	if !bytes.Equal(public, again) {
		t.Fatal("public projection changed signing owner")
	}
	for _, mutate := range []func(*auth.SignedSignInRecord){
		func(r *auth.SignedSignInRecord) { r.State = auth.SignInStateChallengeRequired },
		func(r *auth.SignedSignInRecord) { r.Proof.Method = "otp" },
		func(r *auth.SignedSignInRecord) { r.Proof.Assurance = auth.AssuranceMultiFactor },
		func(r *auth.SignedSignInRecord) { r.Proof.Purpose = "identity.password.change" },
		func(r *auth.SignedSignInRecord) { r.ProofVersion = 0 },
		func(r *auth.SignedSignInRecord) { r.CredentialVersion = 0 },
	} {
		bad := original
		mutate(&bad)
		got, err := key.sign(bad)
		if !errors.Is(err, password.ErrPasswordWork) || got.Proof.ID != "" || len(got.Signature) != 0 {
			t.Fatal("unsupported authentication signed")
		}
	}
	for _, id := range []string{"", "bad key", strings.Repeat("x", 129)} {
		if _, err := NewSigninSigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("bad key ID")
		}
	}
	for _, material := range []ed25519.PrivateKey{nil, make([]byte, 32), make([]byte, 64)} {
		if _, err := NewSigninSigningKey("signin-1", material); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("inconsistent key accepted")
		}
	}
	if _, err := (SigninSigningKey{}).sign(original); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero signing owner")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
		if fmt.Sprintf(verb, key) != "passwordpostgres.SigninSigningKey(redacted)" {
			t.Fatal("signing key diagnostic")
		}
	}
	if _, err := json.Marshal(key); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("key JSON export")
	}
}

func nativeSigninFlow(t testing.TB) (password.SigninRequest, session.PreAuthTransaction, session.DigestKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC)
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewDigestKey(1, bytes.Repeat([]byte{43}, 32))
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{44}, 32))
	token, _ := session.ParseToken(cookie)
	b := session.PreAuthBinding{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.password.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/after", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, err := token.PreAuthDigest(key, b)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte(" synthetic-password "))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Destroy)
	r := password.SigninRequest{TenantID: "tenant", PreAuthID: b.ID, Cookie: auth.NewBearerCredential(cookie), Identifier: "person@example.test", Password: secret, Remember: remember, Origin: b.Intent.Origin, CallbackURL: b.Intent.CallbackURL, Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "ingress"}, Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}}
	return r, flow, key, now
}

func TestNativeSigninRequiresOriginalPreAuthIntent(t *testing.T) {
	r, flow, key, now := nativeSigninFlow(t)
	if err := admitSigninFlow(r, flow, key, "login", 3, now); err != nil {
		t.Fatal("original intent denied", err)
	}
	for _, mutate := range []func(*password.SigninRequest){
		func(r *password.SigninRequest) { r.TenantID = "foreign" },
		func(r *password.SigninRequest) { r.PreAuthID = "AgICAgICAgICAgICAgICAg" },
		func(r *password.SigninRequest) {
			r.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{45}, 32)))
		},
		func(r *password.SigninRequest) { r.Origin = "https://other.test" },
		func(r *password.SigninRequest) { r.CallbackURL = "" },
		func(r *password.SigninRequest) {
			r.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		},
	} {
		bad := r
		mutate(&bad)
		if err := admitSigninFlow(bad, flow, key, "login", 3, now); err == nil {
			t.Fatal("substituted original intent")
		}
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(5 * time.Minute), now.Add(6 * time.Minute)} {
		if admitSigninFlow(r, flow, key, "login", 3, at) == nil {
			t.Fatal("original timeline renewed")
		}
	}
	if admitSigninFlow(r, flow, key, "login", 3, now.Add(5*time.Minute-time.Microsecond)) != nil {
		t.Fatal("exclusive expiry")
	}
	wrong, _ := session.NewDigestKey(1, bytes.Repeat([]byte{46}, 32))
	if admitSigninFlow(r, flow, wrong, "login", 3, now) == nil || admitSigninFlow(r, flow, key, "login", 4, now) == nil || admitSigninFlow(r, flow, key, "other", 3, now) == nil || admitSigninFlow(r, session.PreAuthTransaction{}, key, "login", 3, now) == nil {
		t.Fatal("named key/policy/original missing")
	}
}
