package emailhttp_test

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

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Transport-only doubles. Real native proof/signature/SQL and graph acceptance
// are separate integration journeys, not claims made by this handler fixture.
type requestOwner struct {
	calls, sources, reads int
	proof                 auth.ReauthenticationProof
	last                  email.VerificationSendRequest
	result                func() (email.VerificationSendResult, error)
}

func (s *requestOwner) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	s.reads++
	if id != s.proof.Proof.ID {
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	return auth.SignedReauthenticationRecord{Proof: s.proof}, ctx.Err()
}
func (s *requestOwner) VerificationSendRateSource(ctx context.Context, r email.VerificationSendRequest) (identity.UserID, string, error) {
	s.sources++
	s.last = r
	if r.Validate() != nil {
		return "", "", email.ErrInvalidVerification
	}
	return "original-user", "Canonical@example.test", ctx.Err()
}
func (s *requestOwner) VerificationSend(ctx context.Context, r email.VerificationSendRequest) (email.VerificationSendResult, error) {
	s.calls++
	s.last = r
	return s.result()
}
func (s *requestOwner) ChangeRequestRateSource(ctx context.Context, r email.ChangeRequestRequest) (identity.UserID, string, error) {
	s.sources++
	if r.Validate() != nil {
		return "", "", email.ErrInvalidVerification
	}
	return "original-user", "Canonical@example.test", ctx.Err()
}
func (s *requestOwner) ChangeRequest(ctx context.Context, r email.ChangeRequestRequest) (email.ChangeRequestResult, error) {
	s.calls++
	out, err := s.result()
	return email.ChangeRequestResult(out), err
}

type requestRateBackend struct {
	*backend
	simple []ratelimit.Request
}

func (b *requestRateBackend) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	b.simple = append(b.simple, r)
	return ratelimit.Decision{Allowed: true, Reason: ratelimit.ReasonAllowed, Limit: r.Policy.Limit(), Remaining: r.Policy.Limit() - 1, Reset: r.Now.Add(r.Policy.Period())}, ctx.Err()
}

func emailRequestFixture(t *testing.T, change bool) (emailhttp.RequestConfig, *requestOwner, *http.Request) {
	t.Helper()
	base, _, _ := fixture(t)
	now := time.Unix(1800000000, 0).UTC()
	action := "identity.email.verification-send"
	path := "/v1/email/verification-send"
	field := "address"
	if change {
		action = "identity.email.change-request"
		path = "/v1/email/change-request"
		field = "newAddress"
	}
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant-a", Subject: "original-user", Purpose: "identity.password.verify", Audience: "managed", Method: "password", Assurance: auth.AssuranceSingleFactor, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, SessionID: "original-session", SessionVersion: 1, Action: action}
	owner := &requestOwner{proof: proof}
	id, _ := identity.NewCommandID()
	owner.result = func() (email.VerificationSendResult, error) {
		return email.VerificationSendResult{CommandID: id, Outcome: identity.CommitOutcomeCommitted, DeliveryState: delivery.StateQueued, AddressID: "original-address", IdentifierVersion: 1, VerificationVersion: 1}, nil
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailhttp.RequestConfig{Network: base.Network, Proofs: owner, Cookie: cookie, Origin: base.Origin, PolicyRevision: 9, MaximumDuration: time.Second}
	backend := &requestRateBackend{backend: &backend{}}
	if change {
		cfg.Change = owner
		cfg.CurrentAddressProofPolicy = email.NotifyCurrentAddress
		cfg.SecretRate, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "email-request", Key: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cfg.SecretRate.Close() })
	} else {
		cfg.Verification = owner
		cfg.DeliveryRate, err = identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "email-request", IdentifierKey: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cfg.DeliveryRate.Close() })
	}
	r := request(`{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","` + field + `":"Requested@example.test","callback":"https://tenant.example/finish"}`)
	r.URL.Path = path
	r.RequestURI = path
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"})
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := csrf.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-CSRF-Token", wire)
	r.Header.Set("Idempotency-Key", "original-request-key")
	return cfg, owner, r
}

func TestEmailRequestHTTPClosedInput(t *testing.T) {
	for _, change := range []bool{false, true} {
		for _, kind := range []string{"origin", "csrf", "authorization", "key", "duplicate-key", "duplicate-cookie", "empty", "media", "override", "alias", "duplicate-field", "null", "oversize", "query", "trailer"} {
			t.Run(string(rune('0'+btoi(change)))+kind, func(t *testing.T) {
				cfg, owner, r := emailRequestFixture(t, change)
				want := 400
				switch kind {
				case "origin":
					r.Header.Set("Origin", "https://foreign.example")
					want = 403
				case "csrf":
					r.Header.Del("X-CSRF-Token")
					want = 403
				case "authorization":
					r.Header.Set("Authorization", "Bearer other")
				case "key":
					r.Header.Del("Idempotency-Key")
				case "duplicate-key":
					r.Header.Add("Idempotency-Key", "other")
					want = 421 // The shared network envelope rejects duplicate headers.
				case "duplicate-cookie":
					r.Header.Add("Cookie", "__Host-identity_session=other")
				case "empty":
					r.Body = http.NoBody
					r.ContentLength = 0
				case "media":
					r.Header.Set("Content-Type", "text/plain")
					want = 403 // The selected JSON synchronizer channel rejects this media.
				case "override", "alias", "duplicate-field", "null", "oversize":
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatal(err)
					}
					wire := string(body)
					switch kind {
					case "override":
						wire = strings.TrimSuffix(wire, "}") + `,"tenantID":"foreign"}`
					case "alias":
						wire = strings.Replace(wire, `"proofID"`, `"ProofID"`, 1)
					case "duplicate-field":
						wire = strings.TrimSuffix(wire, "}") + `,"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
					case "null":
						wire = strings.Replace(wire, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":null`, 1)
					case "oversize":
						wire = strings.Replace(wire, "Requested@example.test", strings.Repeat("a", 4097), 1)
					}
					r.Body = io.NopCloser(strings.NewReader(wire))
					r.ContentLength = int64(len(wire))
				case "query":
					r.URL.RawQuery = "userID=other"
				case "trailer":
					r.Trailer = http.Header{"UserID": []string{"other"}}
				}
				var h http.Handler
				var err error
				if change {
					h, err = emailhttp.NewChangeRequestHandler(cfg)
				} else {
					h, err = emailhttp.NewVerificationSendHandler(cfg)
				}
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != want || owner.calls != 0 || owner.sources != 0 || owner.reads != 0 || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "example.test") {
					t.Fatal("invalid input reached original owner", w.Code)
				}
			})
		}
	}
}
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestEmailRequestHTTPConservesOriginalOutcome(t *testing.T) {
	for _, change := range []bool{false, true} {
		for _, kind := range []string{"queued", "unknown", "committed-error", "denied", "pending", "panic"} {
			t.Run(string(rune('0'+btoi(change)))+kind, func(t *testing.T) {
				cfg, owner, r := emailRequestFixture(t, change)
				original := owner.result
				want := 202
				observation := "committed"
				owner.result = func() (email.VerificationSendResult, error) {
					out, _ := original()
					switch kind {
					case "unknown":
						out.Outcome = identity.CommitOutcomeUnknown
						out.DeliveryState = 0
						out.AddressID = ""
						out.IdentifierVersion = 0
						out.VerificationVersion = 0
					case "committed-error":
						return out, errors.New("private Requested@example.test")
					case "denied":
						return email.VerificationSendResult{}, identity.ForbiddenError{}
					case "pending":
						out.Outcome = identity.CommitOutcomeInProgress
						out.DeliveryState = 0
						out.AddressID = ""
						out.IdentifierVersion = 0
						out.VerificationVersion = 0
						out.RetryAfter = time.Second
					case "panic":
						panic("private Requested@example.test")
					}
					return out, nil
				}
				switch kind {
				case "unknown", "committed-error":
					want = 503
				case "denied":
					want = 403
					observation = "unknown"
				case "pending":
					want = 409
					observation = "in_progress"
				case "panic":
					want = 503
					observation = "unknown"
				}
				if kind == "unknown" {
					observation = "unknown"
				}
				var h http.Handler
				var err error
				if change {
					h, err = emailhttp.NewChangeRequestHandler(cfg)
				} else {
					h, err = emailhttp.NewVerificationSendHandler(cfg)
				}
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				var out emailhttp.RequestResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil {
					t.Fatal("invalid response")
				}
				if w.Code != want || owner.calls != 1 || owner.sources != 1 || out.CommitOutcome != observation || out.Queued != (kind == "queued") || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "example.test") || strings.Contains(w.Body.String(), "original-user") {
					t.Fatal("request outcome/custody changed", w.Code, out.CommitOutcome)
				}
			})
		}
	}
}

func TestEmailRequestFeatureSelectsBothActualOperations(t *testing.T) {
	v, _, request := emailRequestFixture(t, false)
	c, _, _ := emailRequestFixture(t, true)
	feature, err := emailhttp.NewFeature(emailhttp.FeatureConfig{VerificationRequest: &v, ChangeRequest: &c})
	if err != nil {
		t.Fatal("selected request feature", err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Email requests", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal("selected request OpenAPI", err)
	}
	for _, action := range []string{"identity.email.verification-send", "identity.email.change-request"} {
		if !strings.Contains(string(document.JSON()), action) {
			t.Fatal("selected route has no wire contract")
		}
	}
	if strings.Contains(string(document.JSON()), "identity.email.verification-confirm") {
		t.Fatal("request selected an unconfigured confirmation")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 202 {
		t.Fatal("documented request did not execute", w.Code)
	}
}
