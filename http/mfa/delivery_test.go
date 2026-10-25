package mfahttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// Native durable authentication is a seam here; actual record/cookie/CSRF
// custody and transport delivery are real. The reference journey proves native
// authentication separately; these fixtures are not a factor verification claim.
func issuance(t *testing.T, c TOTPVerifyConfig, r mfa.TotpVerifyRequest) mfa.TotpVerifyResult {
	t.Helper()
	now := c.Now()
	token, _ := session.NewToken(32)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, string(r.TenantID))
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind("global"), Tenant: bind("tenant"), User: bind("user"), Identifier: bind("identifier"), Credential: bind("credential"), SessionFamily: bind("family"), Session: bind("session"), Authorization: bind("authorization"), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind("factor")}})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	parent := identity.CommandID("CAgICAgICAgICAgICAgICA")
	primary, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: parent, RequestCommandID: "CQkJCQkJCQkJCQkJCQkJCQ", CapabilityID: "parent-proof", IdentifierID: "AwMDAwMDAwMDAwMDAwMDAw", IdentifierVersion: 1, VerificationVersion: 1, AuthenticatedAt: now.Add(-5 * time.Second), ValidUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := remember.Bindings()
	factor, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: r.CommandID, PrimaryCommandID: parent, ContinuationID: identity.CommandID(r.ChallengeID), ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: string(r.FactorID), EnrollmentVersion: 1, FactorAuthorityVersion: 1, ContinuationVersion: 1, Remember: resolved, VerifiedAt: now, ValidUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	state, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: r.TenantID, SessionID: "session-a", SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithMagicLinkMFAAndCSRF(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: r.TenantID, UserID: "user-a", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}, IssuedAt: now, LastActivityAt: now}, primary, factor, state)
	if c.PasswordPrimary {
		spec, _ := record.Bindings()
		spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(parent), Tenant: string(r.TenantID), Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: c.Audience, IssuedAt: now.Add(-5 * time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "credential-a", CredentialVersion: 1}
		record, err = session.NewSessionWithPasswordMFAAndCSRF(spec, factor, state)
	}
	if c.PasskeyPrimary {
		spec, _ := record.Bindings()
		spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(parent), Tenant: string(r.TenantID), Subject: "user-a", Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: session.PasskeyMFAPrimaryPurpose, Audience: c.Audience, IssuedAt: now.Add(-5 * time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "credential-a", CredentialVersion: 1}
		authority, e := spec.Authority.Bindings()
		if e != nil {
			t.Fatal(e)
		}
		authority.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: bind("passkey")}
		spec.Authority, err = session.NewAuthoritySnapshot(authority)
		if err != nil {
			t.Fatal(err)
		}
		record, err = session.NewSessionWithPasskeyMFAAndCSRF(spec, factor, state)
	}
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := c.SessionCookie.Attributes(remember, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Token: token, Cookie: cookie}, CSRFToken: csrf}
}

type commitWriter struct {
	http.ResponseWriter
	before func()
	status int
}

func (w commitWriter) WriteHeader(status int) {
	if w.before != nil {
		w.before()
	}
	if w.status != 0 && status == 200 {
		status = w.status
	}
	w.ResponseWriter.WriteHeader(status)
}

func TestTOTPHTTPFinalCommitCannotDeliverDelayedOrFailedResponse(t *testing.T) {
	for _, mode := range []string{"delay", "changed-status"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body, device := handlerFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			owner.result = func(r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) { return issuance(t, c, r), nil }
			h, err := NewTOTPVerifyHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/mfa", Middleware: identityhttp.Middleware{Name: "commit-boundary", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					wrapped := commitWriter{ResponseWriter: w}
					if mode == "delay" {
						wrapped.before = func() { now = now.Add(time.Minute) }
					} else {
						wrapped.status = 503
					}
					next.ServeHTTP(wrapped, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
			r.RequestURI = r.URL.RequestURI()
			r.RemoteAddr = "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			r.AddCookie(device)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out TOTPVerifyResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.SignedIn || out.SessionID != "" || out.CommitOutcome != "committed" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || owner.calls != 1 {
				t.Fatal("delayed/failed wire commit delivered credentials", w.Code)
			}
		})
	}
}

func TestTOTPHTTPFreshCommitDeliversOnlyMatchingMFA(t *testing.T) {
	for _, mode := range []string{"success", "foreign-factor", "expired-at-commit", "error-with-custody", "password-success", "password-foreign-factor", "password-expired-at-commit", "password-error-with-custody", "password-on-magic-route", "magic-on-password-route"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body, device := handlerFixture(t)
			c.PasswordPrimary = strings.HasPrefix(mode, "password-") && mode != "password-on-magic-route" || mode == "magic-on-password-route"
			initial := c.Now()
			now := initial
			c.Now = func() time.Time { return now }
			owner.result = func(r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
				actual := r
				if strings.HasSuffix(mode, "foreign-factor") {
					actual.FactorID = "CQkJCQkJCQkJCQkJCQkJCQ"
				}
				profile := c
				if mode == "password-on-magic-route" || mode == "magic-on-password-route" {
					profile.PasswordPrimary = !c.PasswordPrimary
				}
				result := issuance(t, profile, actual)
				if strings.HasSuffix(mode, "error-with-custody") {
					return result, identity.UnavailableError{}
				}
				if strings.HasSuffix(mode, "expired-at-commit") {
					now = initial.Add(time.Minute)
				}
				return result, nil
			}
			h, err := NewTOTPVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
			r.RequestURI = r.URL.RequestURI()
			r.RemoteAddr = "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			r.AddCookie(device)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out TOTPVerifyResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatal("invalid result JSON")
			}
			if mode == "success" || mode == "password-success" {
				if w.Code != 200 || !out.SignedIn || out.SessionID != "session-a" || len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "" {
					t.Fatal("fresh owned tuple not delivered", w.Code)
				}
				cookie := w.Result().Cookies()[0]
				if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || strings.Contains(w.Body.String(), cookie.Value) {
					t.Fatal("unsafe bearer delivery")
				}
			} else if out.SignedIn || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("invalid/delayed/error tuple escaped")
			}
		})
	}
}
