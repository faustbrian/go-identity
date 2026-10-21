package anonymoushttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	"github.com/faustbrian/go-identity/session"
)

type observed func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (f observed) ObserveSession(c context.Context, q session.SessionLookup) (session.SessionObservation, error) {
	return f(c, q)
}

type instant func() time.Time

func (f instant) Now() time.Time { return f() }

type upgradeOwner struct {
	anonymous.Upgrader
	result    anonymous.UpgradeResult
	err       error
	calls     int
	request   anonymous.UpgradeRequest
	onUpgrade func()
}

func (o *upgradeOwner) Upgrade(ctx context.Context, r anonymous.UpgradeRequest) (anonymous.UpgradeResult, error) {
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("invalid/unbounded upgrade invocation")
	}
	o.calls++
	o.request = r
	if o.onUpgrade != nil {
		o.onUpgrade()
	}
	return o.result, o.err
}

type upgradeSources struct {
	proof         auth.SignedReauthenticationRecord
	subject       anonymous.AnonymousSubject
	reads, proofs int
	err           error
}

func (s *upgradeSources) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	s.proofs++
	if s.err != nil {
		return auth.SignedReauthenticationRecord{}, s.err
	}
	if _, ok := ctx.Deadline(); !ok || id != s.proof.Proof.Proof.ID {
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	return s.proof, nil
}
func (s *upgradeSources) Read(ctx context.Context, q anonymous.SubjectQuery) (anonymous.AnonymousSubject, error) {
	s.reads++
	if s.err != nil {
		return anonymous.AnonymousSubject{}, s.err
	}
	b, _ := s.subject.Record()
	if _, ok := ctx.Deadline(); !ok || q.UserID != b.UserID || q.TenantID != b.TenantID {
		return anonymous.AnonymousSubject{}, anonymous.ErrSubjectAbsent
	}
	return s.subject, nil
}

func upgradeFixture(t *testing.T) (anonymoushttp.UpgradeConfig, *upgradeOwner, *upgradeSources, func() *http.Request) {
	t.Helper()
	base, _, rate, guestRequest := deletionFixture(t)
	signin, _, _ := signinFixture(t)
	native := freshGuestResult(t, signin)
	spec, err := native.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	now := base.Now()
	spec.IssuedAt, spec.LastActivityAt = now, now
	token, _ := session.NewToken(32)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	spec.Lookup, _ = token.Digest(key, "tenant-a")
	targetWire, _ := token.Reveal()
	spec.SessionID, spec.FamilyID, spec.UserID = "target-session", "target-family", "target-user"
	p := auth.Proof{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Tenant: "tenant-a", Subject: "target-user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "guest-service", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: p, ProofVersion: 1, CredentialID: "target-password", CredentialVersion: 1}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewSessionService(observed(func(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{Session: record, Current: spec.Authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, nil
	}), session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: instant(base.Now), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	guestID := identity.SubjectID("AgICAgICAgICAgICAgICAg")
	subject, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: guestID, TenantID: "tenant-a", UserID: identity.UserID(guestID), CreatedAt: now.Truncate(time.Microsecond), ExpiresAt: now.Truncate(time.Microsecond).Add(time.Hour), State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupDelete})
	if err != nil {
		t.Fatal(err)
	}
	sources := &upgradeSources{proof: auth.SignedReauthenticationRecord{Proof: auth.ReauthenticationProof{Proof: p, SessionID: spec.SessionID, SessionVersion: spec.Version, Action: "identity.anonymous.upgrade"}}, subject: subject}
	id, _ := identity.NewCommandID()
	prep, _ := identity.NewCommandID()
	q := identity.RecoveryQuery{CommandID: id, TenantID: "tenant-a", UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.anonymous.upgrade", RecordID: string(guestID)}
	pq := q
	pq.CommandID, pq.RecordID = prep, ""
	owner := &upgradeOwner{result: anonymous.UpgradeResult{Outcome: identity.CommitOutcomeCommitted, Preparation: pq, Recovery: q, Replayed: true}}
	targetCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	c := anonymoushttp.UpgradeConfig{Network: base.Network, Service: owner, Sessions: sessions, Proofs: sources, Subjects: sources, Rate: base.Rate, GuestCookie: base.Cookie, TargetCookie: targetCookie, Origin: base.Origin, Device: base.Device, PolicyRevision: 1, Audience: signin.Audience, Now: base.Now, MaximumDuration: base.MaximumDuration}
	_ = rate
	tcsrf, _ := session.NewCSRFToken()
	targetCSRF, _ := tcsrf.Reveal()
	return c, owner, sources, func() *http.Request {
		r := replaceBody(guestRequest(), `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[]}`)
		r.URL.Path = "/v1/anonymous/upgrade"
		r.RequestURI = r.URL.RequestURI()
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: targetWire})
		r.Header.Set("X-Target-CSRF-Token", targetCSRF)
		return r
	}
}

func TestUpgradeRequiresExactRetryKeyAndBothOriginalBrowserCustodies(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "missing-key", "duplicate-key", "missing-target", "duplicate-target", "missing-guest", "missing-guest-csrf", "missing-target-csrf", "duplicate-target-csrf", "body-target", "body-proof", "unsupported-conflict", "wrong-origin", "authorization"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, sources, request := upgradeFixture(t)
			r := request()
			want := 400
			switch mode {
			case "replay":
				want = 200
			case "unknown":
				want = 503
				owner.result.Outcome = identity.CommitOutcomeUnknown
				owner.err = identity.UnknownCommitError{CommandID: owner.result.Preparation.CommandID}
			case "missing-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", r.Header.Get("Idempotency-Key"))
			case "missing-target", "missing-guest":
				cookies := r.Cookies()
				r.Header.Del("Cookie")
				for _, cookie := range cookies {
					if mode == "missing-target" && cookie.Name == "__Host-identity_session" || mode == "missing-guest" && cookie.Name == "__Host-identity_guest" {
						continue
					}
					r.AddCookie(cookie)
				}
			case "duplicate-target":
				for _, cookie := range r.Cookies() {
					if cookie.Name == "__Host-identity_session" {
						r.AddCookie(cookie)
					}
				}
			case "missing-guest-csrf":
				r.Header.Del("X-CSRF-Token")
				want = 403
			case "missing-target-csrf":
				r.Header.Del("X-Target-CSRF-Token")
				want = 403
			case "duplicate-target-csrf":
				r.Header.Add("X-Target-CSRF-Token", r.Header.Get("X-Target-CSRF-Token"))
				want = 403
			case "body-target":
				r = replaceBody(r, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[],"target":"other"}`)
			case "body-proof":
				r = replaceBody(r, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[],"proof":{}}`)
			case "unsupported-conflict":
				r = replaceBody(r, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[{"field":"profile.display_name","disposition":"keep_source"}]}`)
			case "wrong-origin":
				r.Header.Set("Origin", "https://foreign.example")
				want = 403
			case "authorization":
				r.Header.Set("Authorization", "Bearer forbidden")
			}
			h, err := anonymoushttp.NewUpgradeHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "target-password") {
				t.Fatalf("wrong upgrade custody/status: %d; native=%d subjects=%d proofs=%d response=%s", w.Code, owner.calls, sources.reads, sources.proofs, w.Body.String())
			}
			if mode == "replay" || mode == "unknown" {
				var out anonymoushttp.UpgradeResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Upgraded || out.Preparation == nil || out.Recovery == nil || out.Preparation.CommandID == out.Recovery.CommandID || owner.calls != 1 {
					t.Fatal("two-command history lost or replay redelivered authority")
				}
				if owner.request.IdempotencyKey == (identity.IdempotencyKey{}) || owner.request.TargetProof != sources.proof.Proof || owner.request.Plan.Target != "target-user" {
					t.Fatal("native request lost actual proof/target/original key")
				}
			} else if owner.calls != 0 || sources.reads != 0 || sources.proofs != 0 {
				t.Fatal("invalid request reached protected owner or directory")
			}
		})
	}
}

func TestUpgradeTransportKeepsStableNativeIntentAcrossRealRetries(t *testing.T) {
	c, owner, _, request := upgradeFixture(t)
	now := c.Now()
	c.Now = func() time.Time { return now }
	h, err := anonymoushttp.NewUpgradeHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 200 {
		t.Fatal("original attempt failed")
	}
	first := owner.request.Caller.Request.Environment.Time
	now = now.Add(time.Second)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 200 {
		t.Fatal("retry failed")
	}
	if owner.calls != 2 || owner.request.Caller.Request.Environment.Time != first || !first.IsZero() {
		t.Fatal("transport inserted a changing clock into exact native retry intent")
	}
}

func TestUpgradeOnlyFreshAcknowledgementDeliversPermanentCustody(t *testing.T) {
	for _, mode := range []string{"fresh", "authority-before-commit", "authority-at-commit", "proof-at-commit", "guest-at-commit", "native-before-commit", "native-at-commit", "native-after-commit", "missing-native-deadline", "committed-error", "foreign-result"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, sources, request := upgradeFixture(t)
			r := request()
			var original session.GetResult
			for _, cookie := range r.Cookies() {
				if cookie.Name == "__Host-identity_session" {
					token, _ := session.ParseToken(cookie.Value)
					credential, _ := session.NewCredential(session.CredentialCookie, token)
					var err error
					original, err = c.Sessions.Get(t.Context(), session.GetRequest{TenantID: "tenant-a", Credential: credential})
					if err != nil || !original.Authenticated {
						t.Fatal("target fixture", err)
					}
				}
			}
			target, _ := original.Session.Bindings()
			signin, _, _ := signinFixture(t)
			signin.Now = c.Now
			fresh := freshGuestResult(t, signin)
			spec, _ := fresh.Session.Session.Bindings()
			spec.UserID, spec.Authentication = target.UserID, target.Authentication
			if mode == "foreign-result" {
				spec.SessionID = target.SessionID
			}
			key, _ := session.NewCSRFKey(1, make([]byte, 32))
			csrfState, err := fresh.CSRFToken.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
			if err != nil {
				t.Fatal(err)
			}
			fresh.Session.Session, err = session.NewSessionWithCSRF(spec, csrfState)
			if err != nil {
				t.Fatal(err)
			}
			fresh.Session.CommandID = owner.result.Recovery.CommandID
			fresh.Session.Cookie, err = c.TargetCookie.Attributes(spec.Remember, c.Now(), spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
			if err != nil {
				t.Fatal(err)
			}
			owner.result.Replayed = false
			owner.result.Session = fresh.Session
			owner.result.Session.DeliveryValidUntil = c.Now().Add(20 * time.Second)
			owner.result.CSRFToken = fresh.CSRFToken
			if mode == "committed-error" {
				owner.err = identity.UnavailableError{}
			}
			now := c.Now()
			commitAt := now
			deliverable := mode == "fresh" || mode == "authority-before-commit" || mode == "native-before-commit"
			switch mode {
			case "missing-native-deadline":
				owner.result.Session.DeliveryValidUntil = time.Time{}
			case "native-before-commit", "native-at-commit", "native-after-commit":
				// Model the native guest-session/capability bound separately:
				// target, proof, guest subject and replacement session stay live.
				deadline := now.Add(3 * time.Second).Truncate(time.Second)
				owner.result.Session.DeliveryValidUntil = deadline
				commitAt = deadline
				if mode == "native-before-commit" {
					commitAt = deadline.Add(-time.Nanosecond)
				} else if mode == "native-after-commit" {
					commitAt = deadline.Add(time.Nanosecond)
				}
			case "authority-before-commit":
				commitAt = original.ValidUntil().Add(-time.Nanosecond)
			case "authority-at-commit":
				commitAt = original.ValidUntil()
			case "proof-at-commit":
				commitAt = now.Add(5 * time.Second)
				sources.proof.Proof.Proof.ExpiresAt = commitAt
			case "guest-at-commit":
				commitAt = now.Add(5 * time.Second).Truncate(time.Microsecond)
				guest, err := sources.subject.Record()
				if err != nil {
					t.Fatal(err)
				}
				guest.ExpiresAt = commitAt
				guest.CreatedAt = commitAt.Add(-15 * time.Minute)
				sources.subject, err = anonymous.NewAnonymousSubject(guest)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Isolate each earliest expiry: other original evidence and the
			// prospective session/device remain live at response commitment.
			requireBrowserDeviceLiveAt(t, c.Device, r, commitAt)
			if _, err := fresh.Session.Session.Lifetime(commitAt); err != nil {
				t.Fatal("session masks selected expiry", err)
			}
			guest, _ := sources.subject.Record()
			if mode != "guest-at-commit" && !commitAt.Before(guest.ExpiresAt) {
				t.Fatal("guest masks selected expiry")
			}
			if mode != "proof-at-commit" && !commitAt.Before(sources.proof.Proof.Proof.ExpiresAt) {
				t.Fatal("proof masks selected expiry")
			}
			if mode != "authority-at-commit" && !commitAt.Before(original.ValidUntil()) {
				t.Fatal("target authority masks selected expiry")
			}
			returned, reads := false, 0
			owner.onUpgrade = func() { returned = true }
			c.Now = func() time.Time {
				if returned {
					reads++
					if reads > 1 {
						return commitAt
					}
				}
				return now
			}
			h, err := anonymoushttp.NewUpgradeHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out anonymoushttp.UpgradeResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Preparation == nil || out.Recovery == nil || out.CommitOutcome != "committed" {
				t.Fatal("lost acknowledged command history")
			}
			if !deliverable {
				if w.Code != 503 || out.Upgraded || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatalf("non-deliverable upgrade leaked custody: %d", w.Code)
				}
				return
			}
			cookies := w.Result().Cookies()
			if w.Code != 200 || !out.Upgraded || len(cookies) != 2 {
				t.Fatalf("fresh upgrade did not deliver exact selected custody: %d", w.Code)
			}
			newCount, cleared := 0, false
			for _, cookie := range cookies {
				if cookie.Name == "__Host-identity_session" {
					newCount++
					if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.MaxAge != 0 {
						t.Fatal("permanent cookie policy lost")
					}
					if _, err := session.ParseToken(cookie.Value); err != nil {
						t.Fatal("invalid delivered permanent session")
					}
				} else if cookie.Name == "__Host-identity_guest" && cookie.MaxAge < 0 {
					cleared = true
				} else {
					t.Fatal("unexpected credential cookie")
				}
			}
			if newCount != 1 || !cleared {
				t.Fatal("guest clear/permanent issuance not independent")
			}
			if _, err := session.ParseCSRFToken(w.Header().Get("X-CSRF-Token")); err != nil {
				t.Fatal("missing permanent synchronizer")
			}
			if _, err := fresh.Session.Token.Reveal(); err == nil {
				t.Fatal("new credential custody reusable")
			}
		})
	}
}

func TestUpgradeUnavailableOriginalOwnerNeverBecomesDeniedOrFresh(t *testing.T) {
	c, owner, sources, request := upgradeFixture(t)
	sources.err = identity.UnavailableError{}
	h, err := anonymoushttp.NewUpgradeHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 503 || owner.calls != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("unavailable original owner was disguised as a caller denial or issuance")
	}
}

func FuzzUpgradeClosedJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[]}`, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":1,"expectedVersion":2,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[]}`, `{"proof":null}`, `{"guestID":"AgICAgICAgICAgICAgICAg","expectedVersion":18446744073709551616,"proofID":"AQEBAQEBAQEBAQEBAQEBAQ","conflicts":[]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			t.Skip()
		}
		c, owner, _, request := upgradeFixture(t)
		h, err := anonymoushttp.NewUpgradeHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, replaceBody(request(), body))
		if owner.calls > 1 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("hostile input repeated mutation or escaped replay custody")
		}
		if owner.calls == 1 && owner.request.Validate() != nil {
			t.Fatal("malformed protected request reached native owner")
		}
	})
}
