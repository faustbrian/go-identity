package ssohttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-rate-limit/v2/memory"
	"github.com/faustbrian/go-sso"
)

type directoryTestClock func() time.Time

func (f directoryTestClock) Now() time.Time { return f() }

type directorySessionReader func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (f directorySessionReader) ObserveSession(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
	return f(ctx, q)
}

type directoryTestOwner struct {
	generation DirectoryGeneration
	completion identity.CommandID
	started    int
	status     int
	canceled   int
}

func (p *directoryTestOwner) StartDirectorySync(_ context.Context, b DirectoryBrowser, r DirectoryStartRequest) (DirectoryGeneration, identity.CommandResult, error) {
	p.started++
	if b.TenantID != testTenant || b.Network.String() != "192.0.2.17" || b.CSRF == (session.CSRFToken{}) || r.ProviderID != p.generation.ProviderID || r.ProviderVersion != 3 || r.MappingVersion != 2 || r.Mode != "apply" {
		return DirectoryGeneration{}, identity.CommandResult{}, sso.ErrForbidden
	}
	return p.generation, p.receipt(directoryStart, p.generation.ID, 0), nil
}

func (p *directoryTestOwner) StatusDirectorySync(_ context.Context, b DirectoryBrowser, id identity.CommandID) (DirectoryGeneration, error) {
	p.status++
	if b.TenantID != testTenant || b.CSRF != (session.CSRFToken{}) || id != p.generation.ID {
		return DirectoryGeneration{}, sso.ErrForbidden
	}
	return p.generation, nil
}

func (p *directoryTestOwner) CancelDirectorySync(_ context.Context, b DirectoryBrowser, id identity.CommandID, version uint64) (DirectoryGeneration, identity.CommandResult, error) {
	p.canceled++
	if b.TenantID != testTenant || b.CSRF == (session.CSRFToken{}) || id != p.generation.ID || version != 1 {
		return DirectoryGeneration{}, identity.CommandResult{}, sso.ErrForbidden
	}
	p.generation.State, p.generation.Version = "canceling", 2
	return p.generation, p.receipt(directoryCancel, p.completion, version), nil
}

func (p *directoryTestOwner) receipt(op string, command identity.CommandID, before uint64) identity.CommandResult {
	descriptor := identity.FeatureOperation{Owner: "sso", OperationID: op, SchemaID: strings.Replace(op, "identity.sso.", "sso-", 1) + "-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return identity.CommandResult{Binding: identity.CommandBinding{CommandID: command, TenantID: testTenant, UserID: "directory-owner", ActorID: "directory-owner", ActorKind: authorization.SubjectUser, OperationID: op, SchemaID: descriptor.SchemaID, SchemaVersion: 1, PolicyID: "directory-test", PolicyVersion: 1, RecordID: string(p.generation.ID), CorrelationID: string(command)}, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "original-event", Feature: &identity.FeatureReceipt{Operation: descriptor, BeforeVersion: before, AfterVersion: before + 1}}
}

type directoryTestRate struct{ operations []string }

func (*directoryTestRate) Configured() bool { return true }

func (r *directoryTestRate) AdmitDirectorySync(_ context.Context, _ identityhttp.NetworkFacts, operation string, user identity.UserID) (time.Duration, error) {
	if user != "directory-owner" {
		return 0, identityhttp.ErrInvalidInput
	}
	r.operations = append(r.operations, operation)
	return 0, nil
}

func TestDirectorySyncHTTPSelectionAndAuthority(t *testing.T) {
	c, owner, rate, cookie, csrf := directoryHTTPFixture(t)
	descriptors := func(features ...identityhttp.Feature) (http.Handler, identityhttp.OpenAPIDocument) {
		t.Helper()
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: features})
		if err != nil {
			t.Fatal(err)
		}
		handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		return handler, document
	}
	feature, err := NewDirectorySyncFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	discoveryConfig, _, _ := discoveryFixture(t)
	discovery, err := NewFeature(discoveryConfig)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso", Operations: append(discovery.Operations(), feature.Operations()...)})
	if err != nil {
		t.Fatal(err)
	}
	h, doc := descriptors(combined)
	off, noDoc := descriptors()
	if !strings.Contains(string(doc.JSON()), `"operationId":"identity.sso.directory-sync-cancel"`) || !strings.Contains(string(doc.JSON()), `"operationId":"identity.sso.discover"`) || strings.Contains(string(doc.JSON()), "directory-sync-apply") || strings.Contains(string(noDoc.JSON()), "directory-sync-") {
		t.Fatal("wrong selected OpenAPI scope")
	}
	request := func(method, target, body string) *http.Request {
		var input io.Reader
		if body != "" {
			input = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, target, input)
		r.Host, r.TLS, r.RemoteAddr = "tenant.example", &tls.ConnectionState{}, "192.0.2.17:32100"
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: cookie})
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://tenant.example")
			r.Header.Set("X-CSRF-Token", csrf)
		}
		return r
	}
	serve := func(handler http.Handler, r *http.Request, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got status %d, want %d (%s)", r.Method, r.URL.Path, w.Code, want, w.Body.String())
		}
		return w
	}
	const startBody = `{"providerID":"configured-provider","providerVersion":3,"mappingVersion":2,"mode":"apply"}`
	start := func() *http.Request {
		r := request(http.MethodPost, "/v1/sso/directory-sync-start", startBody)
		r.Header.Set("Idempotency-Key", "original-directory-start")
		return r
	}
	serve(off, start(), 404)
	serve(h, request(http.MethodPost, "/v1/sso/directory-sync-apply", `{}`), 404)
	for _, sample := range []struct {
		mutate func(*http.Request)
		want   int
	}{
		{func(r *http.Request) { r.Header.Del("Idempotency-Key") }, 400},
		{func(r *http.Request) { r.Header.Add("Idempotency-Key", "second-key") }, 400},
		{func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }, 403},
		{func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{func(r *http.Request) { r.Header.Set("Authorization", "Bearer mixed") }, 400},
		{func(r *http.Request) { r.Header.Del("Cookie") }, 403},
		{func(r *http.Request) { r.Host = "other.example" }, 403},
	} {
		r := start()
		sample.mutate(r)
		serve(h, r, sample.want)
	}
	for _, input := range []string{
		strings.Replace(startBody, `"mode":"apply"`, `"mode":"apply","mode":"dry-run"`, 1),
		strings.Replace(startBody, `"mappingVersion":2`, `"MappingVersion":2`, 1),
		strings.Replace(startBody, `"mode":"apply"`, `"mode":"apply","sourceCursor":"not a native checkpoint"`, 1),
		strings.Replace(startBody, `"providerVersion":3`, `"providerVersion":0`, 1),
	} {
		r := request(http.MethodPost, "/v1/sso/directory-sync-start", input)
		r.Header.Set("Idempotency-Key", "original-directory-start")
		serve(h, r, 400)
	}
	if owner.started != 0 || len(rate.operations) != 0 {
		t.Fatal("hostile input reached native work or administrative rate")
	}
	started := serve(h, start(), 200)
	if started.Header().Get("Cache-Control") != "no-store" || !strings.Contains(started.Body.String(), string(owner.generation.ID)) || strings.Contains(started.Body.String(), "directory-owner") {
		t.Fatal("start did not return bounded credential-free generation metadata")
	}
	statusTarget := "/v1/sso/directory-sync-status?generationID=" + string(owner.generation.ID)
	read := serve(h, request(http.MethodGet, statusTarget, ""), 200)
	if !strings.Contains(read.Body.String(), `"version":1`) || !strings.Contains(read.Body.String(), `"appliedCount":0`) {
		t.Fatal("status omitted the exact cancellation version or zero counters")
	}
	serve(h, request(http.MethodGet, statusTarget+"&generationID="+string(owner.generation.ID), ""), 400)
	cancel := func() *http.Request {
		return request(http.MethodPost, "/v1/sso/directory-sync-cancel", `{"generationID":"`+string(owner.generation.ID)+`","expectedVersion":1}`)
	}
	r := cancel()
	r.Header.Set("Idempotency-Key", "forbidden-on-natural-repeat")
	serve(h, r, 400)
	for range 2 {
		stopped := serve(h, cancel(), 200)
		if !strings.Contains(stopped.Body.String(), `"stopped":true`) || !strings.Contains(stopped.Body.String(), `"reconciliationRequired":true`) || !strings.Contains(stopped.Body.String(), `"state":"canceling"`) {
			t.Fatal("canceling was not distinguished from fully settled cancellation")
		}
	}
	if owner.started != 1 || owner.status != 1 || owner.canceled != 2 || strings.Join(rate.operations, ",") != directoryStart+","+directoryCancel+","+directoryCancel {
		t.Fatal("operations did not use their exact native/rate boundaries")
	}
}

func FuzzDirectorySyncStartWire(f *testing.F) {
	f.Add(`{"providerID":"configured-provider","providerVersion":3,"mappingVersion":2,"mode":"apply"}`)
	f.Add(`{"providerID":"configured-provider","providerVersion":3,"mappingVersion":2,"mode":"dry-run","sourceCursor":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Add(`{"providerID":"configured-provider","providerVersion":3,"mappingVersion":2,"mode":"apply","sourceCursor":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 2048 {
			return
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal([]byte(input), &raw) != nil {
			return
		}
		parsed, err := directoryDecodeStart(raw, identity.IdempotencyKey{})
		if err != nil {
			return
		}
		if !directoryProviderID(parsed.ProviderID) || parsed.ProviderVersion == 0 || parsed.MappingVersion == 0 || !directoryMode(parsed.Mode) {
			t.Fatal("accepted unbounded provider or invalid generation selection")
		}
		if _, supplied := raw["sourceCursor"]; supplied && parsed.Checkpoint == ([32]byte{}) {
			t.Fatal("accepted a supplied zero checkpoint as source authority")
		}
	})
}

func directoryHTTPFixture(t *testing.T) (DirectorySyncConfig, *directoryTestOwner, *directoryTestRate, string, string) {
	t.Helper()
	config, _, _ := discoveryFixture(t)
	now := config.Now()
	token, _ := session.NewToken(32)
	cookieWire, _ := token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, string(testTenant))
	csrf, _ := session.NewCSRFToken()
	csrfWire, _ := csrf.Reveal()
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: testTenant, SessionID: "session-directory", SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	b := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, _ := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	record, err := session.NewSessionWithCSRF(session.SessionSpec{SessionID: "session-directory", FamilyID: "family-directory", TenantID: testTenant, UserID: "directory-owner", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: string(testTenant), Subject: "directory-owner", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-directory", CredentialVersion: 1}}, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewSessionService(directorySessionReader(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, nil
	}), session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: directoryTestClock(config.Now), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := memory.New(memory.Options{MaxKeys: 128, Shards: 1})
	t.Cleanup(func() { store.Close() })
	safe, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: testSharedRate{store}, Namespace: "directory-test", Now: config.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { safe.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	id, _ := identity.NewCommandID()
	cancelID, _ := identity.NewCommandID()
	owner := &directoryTestOwner{generation: DirectoryGeneration{ID: id, ProviderID: "configured-provider", Version: 1, ProviderVersion: 3, MappingVersion: 2, State: "running", Mode: "apply", Checkpoint: [32]byte{1}}, completion: cancelID}
	rate := new(directoryTestRate)
	return DirectorySyncConfig{Network: config.Network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, Cookie: cookie, Sessions: sessions, SafeRate: safe, AdminRate: rate, Owner: owner, Now: config.Now, MaximumDuration: time.Second}, owner, rate, cookieWire, csrfWire
}
