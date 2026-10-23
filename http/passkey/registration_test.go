package passkeyhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	"github.com/faustbrian/go-rate-limit/v2/memory"
	webauthn "github.com/faustbrian/go-webauthn"
)

type observedSession struct {
	observation session.SessionObservation
	reads       int
}

func (o *observedSession) ObserveSession(ctx context.Context, _ session.SessionLookup) (session.SessionObservation, error) {
	o.reads++
	return o.observation, ctx.Err()
}

type transportClock struct{ now func() time.Time }

func (c transportClock) Now() time.Time { return c.now() }

type deniedEnrollment struct {
	options, sources, completions, proofReads int
	proof                                     auth.ReauthenticationProof
	last                                      passkey.KeyedRegistrationOptionsRequest
}

func (d *deniedEnrollment) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	d.proofReads++
	if id != d.proof.Proof.ID {
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	return auth.SignedReauthenticationRecord{Proof: d.proof}, ctx.Err()
}
func (d *deniedEnrollment) KeyedRegistrationOptions(_ context.Context, r passkey.KeyedRegistrationOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error) {
	d.options++
	d.last = r
	return passkey.KeyedRegistrationOptionsResult{}, identity.ForbiddenError{}
}
func (d *deniedEnrollment) RegistrationRateSource(context.Context, passkey.RegistrationCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	d.sources++
	return passkey.CeremonyRateSource{}, identity.ForbiddenError{}
}
func (d *deniedEnrollment) Register(context.Context, passkey.RegistrationCompletion) (webauthn.VerifiedRegistration, error) {
	d.completions++
	return webauthn.VerifiedRegistration{}, identity.ForbiddenError{}
}

// The observation is a controlled IO boundary. Positive custody is created by
// the actual SessionService, not a caller-authored GetResult. Native/proof ports
// only deny here; actual signed-proof/commit success belongs to Reference PG.
func registrationFixture(t *testing.T) (RegistrationConfig, *deniedEnrollment, *observedSession, *http.Cookie, *http.Cookie, string) {
	t.Helper()
	signin, _, _, device := signinFixture(t)
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := token.Reveal()
	lookup, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(lookup, "tenant-a")
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), SessionFamily: binding("family"), Session: binding("session"), Authorization: binding("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := signin.Now()
	proof := auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFToken()
	csrfWire, _ := csrf.Reveal()
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: "tenant-a", SessionID: "session-a", SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}}, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	reader := &observedSession{observation: session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}}
	sessions, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity", Clock: transportClock{signin.Now}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}})
	if err != nil {
		t.Fatal(err)
	}
	proof.Purpose = "identity.password.verify"
	owner := &deniedEnrollment{proof: auth.ReauthenticationProof{Proof: proof, SessionID: "session-a", SessionVersion: 1, Action: "identity.passkey.register-options"}}
	return RegistrationConfig{Network: signin.Network, Sessions: sessions, Proofs: owner, Service: owner, OptionsRate: signin.OptionsRate, VerificationRate: signin.VerificationRate, Origin: signin.Origin, SessionCookie: signin.SessionCookie, CSRFKeys: []session.CSRFKey{csrfKey}, Device: signin.Device, PolicyRevision: signin.PolicyRevision, Audience: signin.Audience, Now: signin.Now, MaximumDuration: signin.MaximumDuration}, owner, reader, &http.Cookie{Name: "__Host-identity_session", Value: wire}, device, csrfWire
}

func registrationRequest(operation, body string, cookie, device *http.Cookie, csrf string) *http.Request {
	r := signinRequest(operation, body, cookie, device)
	r.Header.Del("Idempotency-Key")
	if operation == "register-options" {
		r.Header.Set("Idempotency-Key", "original-register-options")
	}
	r.Header.Set("X-CSRF-Token", csrf)
	return r
}

func TestRegistrationOptionsUsesActualSessionSynchronizerAndOwnedProofLookup(t *testing.T) {
	c, owner, reader, cookie, device, csrf := registrationFixture(t)
	h, err := NewRegistrationOptionsHandler(c)
	if err != nil || reader.reads != 0 || owner.proofReads != 0 {
		t.Fatal("construction performed IO", err)
	}
	r := registrationRequest("register-options", `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, cookie, device, csrf)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || owner.options != 1 || owner.proofReads != 1 || owner.last.Primary.Proof != owner.proof || owner.last.Primary.CommandID != "" || owner.last.Primary.RecordID != "" || owner.last.Primary.TargetSubjectID != "" || owner.last.Primary.Caller.Request.Subject.ID != "user-a" || owner.last.Primary.CSRFToken == (session.CSRFToken{}) {
		t.Fatal("transport reconstructed proof, changed key ownership or bypassed session admission", w.Code)
	}
	for _, mutation := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43)) }, func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }, func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") }, func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") }} {
		r := registrationRequest("register-options", `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, cookie, device, csrf)
		mutation(r)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.options != 1 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("invalid registration custody reached native options", w.Code)
		}
	}
}

func TestRegistrationCompletionNeedsItsDistinctOwnedActionProofAndSource(t *testing.T) {
	c, owner, _, cookie, device, csrf := registrationFixture(t)
	h, err := NewRegistrationVerifyHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, registrationRequest("register-verify", body, cookie, device, csrf))
	if w.Code != 403 || owner.sources != 0 || owner.completions != 0 {
		t.Fatal("options proof substituted for verification proof", w.Code)
	}
	owner.proof.Action = "identity.passkey.register-verify"
	owner.proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAABA"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, registrationRequest("register-verify", strings.Replace(body, "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAABA", 1), cookie, device, csrf))
	if w.Code != 403 || owner.sources != 1 || owner.completions != 0 {
		t.Fatal("source denial reached registration mutation", w.Code)
	}
}

type deniedInventory struct {
	calls int
	last  passkey.InventoryRequest
}

func (d *deniedInventory) List(_ context.Context, r passkey.InventoryRequest) (passkey.InventoryPage, error) {
	d.calls++
	d.last = r
	return passkey.InventoryPage{}, identity.ForbiddenError{}
}

func TestInventoryUsesActualSessionAndRejectsAlternateScope(t *testing.T) {
	c, _, _, cookie, _, _ := registrationFixture(t)
	store, err := memory.New(memory.Options{MaxKeys: 512, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &parserRates{store}, Namespace: "passkey-list", Now: c.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	owner := &deniedInventory{}
	h, err := NewListHandler(InventoryConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: rate, SessionCookie: c.SessionCookie, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	r := signinRequest("list", "", cookie, nil)
	r.Method = http.MethodGet
	r.Body = http.NoBody
	r.Header.Del("Content-Type")
	r.Header.Del("Origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || owner.calls != 1 || owner.last.Caller.Request.Subject.ID != "user-a" || owner.last.Credential.Kind() != session.CredentialCookie || owner.last.AttemptID == "" {
		t.Fatal("list bypassed original session or selected a target", w.Code)
	}
	for _, query := range []string{"userID=other", "tenantID=other", "limit=101", "limit=0", "limit=1&limit=2", "after=bad%00cursor"} {
		r := signinRequest("list", "", cookie, nil)
		r.Method = http.MethodGet
		r.Body = http.NoBody
		r.Header.Del("Content-Type")
		r.Header.Del("Origin")
		r.URL.RawQuery = query
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.calls != 1 {
			t.Fatal("alternate list scope reached native inventory", w.Code)
		}
	}
}
