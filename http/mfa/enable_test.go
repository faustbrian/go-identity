package mfahttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

func ioBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

func TestEnableHTTPRequiresNativeCookieComposition(t *testing.T) {
	if handler, err := NewEnableHandler(EnableConfig{}); err == nil || handler != nil {
		t.Fatal("unconfigured enrollment HTTP acquired mutation authority")
	}
}

func TestEnableHTTPFeatureIsExplicitAndIndependentOfLogin(t *testing.T) {
	c, owner, _, _, request := enableFixture(t)
	f, err := NewFeature(FeatureConfig{Enable: &c})
	if err != nil {
		t.Fatal("native enrollment selection required unrelated login", err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || len(operations) != 1 || operations[0].Record.OperationID != "identity.mfa.enable" {
		t.Fatal("selection exposed missing or unrelated routes", err)
	}
	w := httptest.NewRecorder()
	operations[0].Handler.ServeHTTP(w, request)
	if w.Code != 200 || owner.calls != 1 {
		t.Fatal("selected descriptor did not execute enrollment", w.Code)
	}
}

type enableClock struct{ now time.Time }

func (c *enableClock) Now() time.Time { return c.now }

type enableReader struct {
	observation session.SessionObservation
	calls       int
}

func (s *enableReader) ObserveSession(ctx context.Context, _ session.SessionLookup) (session.SessionObservation, error) {
	s.calls++
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded session read")
	}
	return s.observation, nil
}

// These ports test transport conservation, not signatures or SQL atomicity.
type enableOwner struct {
	proof        auth.ReauthenticationProof
	last         mfa.EnableRequest
	result       mfa.EnableResult
	err          error
	reads, calls int
	after        func()
}

func (o *enableOwner) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	o.reads++
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded proof read")
	}
	if o.after != nil {
		o.after()
	}
	if o.proof.Proof.ID != id {
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	return auth.SignedReauthenticationRecord{Proof: o.proof}, nil
}
func (o *enableOwner) Enable(ctx context.Context, r mfa.EnableRequest) (mfa.EnableResult, error) {
	o.calls++
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded enrollment")
	}
	o.last = r
	return o.result, o.err
}
func (*enableOwner) RecoverEnable(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.EnableResult, error) {
	return mfa.EnableResult{}, errors.New("unused")
}
func enableFixture(t *testing.T) (EnableConfig, *enableOwner, *enableReader, *enableClock, *http.Request) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	clock := &enableClock{now: now}
	reader := &enableReader{}
	owner := &enableOwner{}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, "tenant-a")
	b := func(s string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: s, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	proof := auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reader.observation = session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}
	sessions, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: &strictRate{}, Namespace: "enable-test", Key: [32]byte{1}, Now: clock.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	c := EnableConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Sessions: sessions, Proofs: owner, Enrollment: owner, Rate: limiter, Cookie: cookie, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 2}, PolicyRevision: 1, Now: clock.Now, MaximumDuration: time.Second}
	proof.Purpose = "identity.password.verify"
	owner.proof = auth.ReauthenticationProof{Proof: proof, SessionID: "session-a", SessionVersion: 1, Action: "identity.mfa.enable"}
	owner.result = mfa.EnableResult{CommandID: "enable-command", Outcome: identity.CommitOutcomeCommitted, Enrollment: mfa.Enrollment{ID: "enrollment-a", FactorMethod: "totp", ExpiresAt: now.Add(time.Minute), Version: 1}}
	r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/enable", strings.NewReader(`{"proofID":"abcdefghijklmnopqrstuv"}`))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "198.51.100.7:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "original-byte-key")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
	r.AddCookie(&http.Cookie{Name: cookieName(c.Cookie), Value: wire})
	return c, owner, reader, clock, r
}
func cookieName(p session.CookiePolicy) string { a, _ := p.DeletionAttributes(); return a.Name }

func TestEnableHTTPConservesNativeCustodyAndDestroysOutput(t *testing.T) {
	for _, mode := range []string{"fresh", "retry", "error", "unknown", "stale", "foreign-proof", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, clock, r := enableFixture(t)
			var secrets []primitive.Secret
			if mode != "retry" {
				for _, text := range []string{"synthetic-code-a", "synthetic-code-b"} {
					code, _ := primitive.NewSecret([]byte(text))
					secrets = append(secrets, code)
				}
				owner.result.RecoveryMaterial.Codes = secrets
			}
			switch mode {
			case "error":
				owner.err = identity.ForbiddenError{}
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "stale":
				owner.after = func() { clock.now = clock.now.Add(21 * time.Second) }
			case "foreign-proof":
				owner.proof.Proof.Subject = "foreign"
			case "cancel":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				owner.after = cancel
			}
			h, err := NewEnableHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			w.Header().Set("Authorization", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Authorization") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
				t.Fatal("credential or cache boundary escaped")
			}
			if mode == "fresh" || mode == "retry" {
				if w.Code != 200 || owner.calls != 1 || owner.last.Validate() != nil || owner.last.CSRFToken == (session.CSRFToken{}) || owner.last.Session.Token() == "" {
					t.Fatal("native cookie custody not conserved", w.Code)
				}
				var out map[string]json.RawMessage
				if json.Unmarshal(w.Body.Bytes(), &out) != nil {
					t.Fatal("response not JSON")
				}
				_, codes := out["recoveryCodes"]
				if codes != (mode == "fresh") {
					t.Fatal("retry disclosure changed")
				}
			} else {
				if w.Code == 200 || strings.Contains(w.Body.String(), "synthetic-code") {
					t.Fatal("non-deliverable result disclosed recovery material")
				}
				if mode == "unknown" && (!strings.Contains(w.Body.String(), `"commitOutcome":"unknown"`) || !strings.Contains(w.Body.String(), `"commandID":"enable-command"`)) {
					t.Fatal("ambiguous original command lost its recovery locator")
				}
			}
			if mode == "fresh" || mode == "error" || mode == "unknown" {
				for _, code := range secrets {
					if code.Len() != 0 {
						t.Fatal("output owner not destroyed")
					}
				}
			} else {
				for _, code := range secrets {
					code.Destroy()
				}
			}
			if (mode == "stale" || mode == "foreign-proof" || mode == "cancel") && owner.calls != 0 {
				t.Fatal("invalid original evidence reached mutation")
			}
		})
	}
}

func TestEnableHTTPRejectsHostileInputBeforeOwners(t *testing.T) {
	for _, mode := range []string{"origin", "authorization", "csrf", "key", "cookie", "duplicate-cookie", "unknown-field", "duplicate-field", "null", "query", "escaped-path", "method", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, reader, _, r := enableFixture(t)
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "authorization":
				r.Header.Set("Authorization", "Bearer forbidden")
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "key":
				r.Header.Del("Idempotency-Key")
			case "cookie":
				r.Header.Del("Cookie")
			case "duplicate-cookie":
				r.AddCookie(r.Cookies()[0])
			case "unknown-field":
				r.Body = ioBody(`{"proofID":"abcdefghijklmnopqrstuv","userID":"foreign"}`)
			case "duplicate-field":
				r.Body = ioBody(`{"proofID":"abcdefghijklmnopqrstuv","proofID":"abcdefghijklmnopqrstuv"}`)
			case "null":
				r.Body = ioBody(`{"proofID":null}`)
			case "query":
				r.URL.RawQuery = "x=1"
			case "escaped-path":
				r.URL.RawPath = "/v1/mfa/%65nable"
			case "method":
				r.Method = http.MethodGet
			case "tenant":
				r.Host = "foreign.example"
			}
			h, err := NewEnableHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || reader.calls != 0 || owner.reads != 0 || owner.calls != 0 {
				t.Fatal("hostile input reached owner", mode, w.Code)
			}
		})
	}
}
