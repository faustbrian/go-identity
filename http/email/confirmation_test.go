package emailhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Counting is tested at the strict native port; native SQL atomicity remains
// independently owned by rate-limit. This seam observes transport dimensions.
type backend struct {
	ratelimit.StrictBackend
	requests []ratelimit.AtomicBatchRequest
	failAt   int
}

func (*backend) Name() string { return "confirmation-test-only" }
func (b *backend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("missing rate deadline")
	}
	b.requests = append(b.requests, r)
	if b.failAt == len(b.requests) {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	d := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}
	for _, q := range r.Requests {
		d.Decisions = append(d.Decisions, ratelimit.Decision{Allowed: true, Reason: ratelimit.ReasonAllowed, Limit: q.Policy.Limit(), Remaining: q.Policy.Limit() - 1, Reset: q.Now.Add(q.Policy.Period())})
	}
	return d, nil
}

type owner struct {
	t              *testing.T
	b              *backend
	sources, calls int
	last           email.VerificationConfirmRequest
	result         func(email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
	sourceErr      error
}

func (s *owner) RegistrationVerificationRateSource(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	s.sources++
	if _, ok := ctx.Deadline(); !ok || p.ValidateBounds(32, 4096) != nil || len(s.b.requests) != 1 || len(s.b.requests[0].Requests) != 1 || callback != "https://tenant.example/finish" || caller.Request.Tenant != "tenant-a" || caller.Request.Resource.ID != "" || caller.Request.Subject.ID != "confirmation-entry" {
		s.t.Error("wrong trusted source or pre-proof budget")
	}
	if s.sourceErr != nil {
		return "", "", 0, s.sourceErr
	}
	return "original-user", "original-issued-grant", time.Hour, nil
}

func receipt(t *testing.T, r email.VerificationConfirmRequest, outcome identity.CommitOutcome, replayed bool, address bool) email.VerificationConfirmResult {
	t.Helper()
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: "original-user", RecordID: "original-address", ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.email.verification-confirm"}
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	out := email.VerificationConfirmResult{Outcome: outcome, Recovery: recovery, Replayed: replayed}
	if address {
		now := time.Unix(1800000000, 0).UTC()
		state := identity.IdentifierState{User: identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 2}, AuthorityVersion: 2, Identifiers: []identity.Identifier{{ID: identity.IdentifierID(q.RecordID), UserID: q.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", Verified: true, Version: 2}}, Verifications: []identity.Verification{{IdentifierID: identity.IdentifierID(q.RecordID), State: identity.VerificationVerified, VerifiedAt: now, Version: 2}}}
		out.Address, err = identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: q.TenantID, UserID: q.UserID, IdentifierID: identity.IdentifierID(q.RecordID), State: state, ObservedAt: now, Values: identity.IdentifierValuesIncluded})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestConfirmationRejectsInputAndCredentialAlternatives(t *testing.T) {
	for _, name := range []string{"extra", "alias", "duplicate", "null", "authorization", "key", "query", "trailer", "origin", "host", "http", "method", "path"} {
		t.Run(name, func(t *testing.T) {
			c, s, body := fixture(t)
			r := request(body)
			want := 400
			switch name {
			case "extra":
				r = request(strings.TrimSuffix(body, "}") + `,"userID":"other"}`)
			case "alias":
				r = request(strings.Replace(body, `"token":`, `"Token":`, 1))
			case "duplicate":
				r = request(strings.TrimSuffix(body, "}") + `,"callback":"https://tenant.example/finish"}`)
			case "null":
				r = request(strings.TrimSuffix(body, "}") + `,"extra":null}`)
			case "authorization":
				r.Header.Set("Authorization", "Bearer other")
			case "key":
				r.Header.Set("Idempotency-Key", "other")
			case "query":
				r.URL.RawQuery = "token=other"
			case "trailer":
				r.Trailer = http.Header{"Token": []string{"other"}}
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				want = 403
			case "host":
				r.Host = "foreign.example"
				want = 421
			case "http":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			case "method":
				r.Method = "GET"
				want = 405
			case "path":
				r.URL.Path += "/"
				want = 404
			}
			h, err := emailhttp.NewConfirmationHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || s.calls != 0 || s.sources != 0 || len(s.b.requests) != 0 || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "other") {
				t.Fatal("unsafe input reached protected owner", w.Code)
			}
		})
	}
}

func TestConfirmationConservesOutcomesAndDisclosure(t *testing.T) {
	for _, mode := range []string{"fresh", "unknown", "committed-error", "replay-payload", "foreign-scope", "cancel", "panic", "in-progress", "native-pending", "native-conflict", "foreign-conflict", "pending-cancel", "pending-untrusted-error"} {
		t.Run(mode, func(t *testing.T) {
			c, s, body := fixture(t)
			r := request(body)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			want := 503
			observed := "committed"
			s.result = func(r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
				out := receipt(t, r, identity.CommitOutcomeCommitted, false, true)
				switch mode {
				case "fresh":
					return out, nil
				case "unknown":
					out = receipt(t, r, identity.CommitOutcomeUnknown, false, false)
				case "committed-error":
					return out, errors.New("private synthetic@example.test")
				case "replay-payload":
					out.Replayed = true
				case "foreign-scope":
					q, _ := out.Recovery.Bindings()
					q.UserID = "foreign"
					out.Recovery, _ = email.NewVerificationRecovery(q)
					out.Address = identity.IdentifierProjection{}
				case "cancel":
					cancel()
				case "panic":
					panic("private synthetic@example.test")
				case "in-progress", "native-pending", "pending-cancel", "pending-untrusted-error":
					out = receipt(t, r, identity.CommitOutcomeInProgress, false, false)
					out.RetryAfter = time.Second
					if mode == "native-pending" {
						return out, identity.UnavailableError{}
					}
					if mode == "pending-cancel" {
						cancel()
						return out, context.Canceled
					}
					if mode == "pending-untrusted-error" {
						return out, errors.New("private synthetic@example.test")
					}
				case "native-conflict":
					return receipt(t, r, identity.CommitOutcomeConflict, false, false), identity.ConflictError{}
				case "foreign-conflict":
					return receipt(t, r, identity.CommitOutcomeConflict, false, false), identity.ConflictError{CommandID: "foreign"}
				}
				return out, nil
			}
			if mode == "fresh" {
				want = 200
			}
			if mode == "unknown" || mode == "panic" {
				observed = "unknown"
			}
			if mode == "in-progress" || mode == "native-pending" || mode == "pending-cancel" || mode == "pending-untrusted-error" {
				observed = "in_progress"
				if mode == "in-progress" || mode == "native-pending" {
					want = 409
				}
			}
			if mode == "native-conflict" {
				want, observed = 409, "conflict"
			}
			if mode == "foreign-conflict" {
				observed = "conflict"
			}
			h, err := emailhttp.NewConfirmationHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out emailhttp.ConfirmationResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatal("invalid response")
			}
			if w.Code != want || s.calls != 1 || out.CommitOutcome != observed || len(w.Result().Cookies()) != 0 {
				t.Fatal("native outcome lost", w.Code, out.CommitOutcome)
			}
			if observed == "in_progress" && want == 409 && w.Header().Get("Retry-After") != "1" {
				t.Fatal("pending attempt lost its bounded retry delay")
			}
			if mode == "fresh" {
				if !out.Confirmed || out.Address == nil || out.Address.Email != "synthetic@example.test" || out.Address.IdentifierVersion != 2 {
					t.Fatal("fresh committed projection withheld")
				}
			} else if out.Confirmed || out.Address != nil || strings.Contains(w.Body.String(), "synthetic@example.test") || strings.Contains(w.Body.String(), "private") {
				t.Fatal("failure disclosed personal/secret output")
			}
		})
	}
}

func TestConfirmationRateAndSourceFailureNeverExecute(t *testing.T) {
	for _, phase := range []string{"ip", "challenge", "source"} {
		t.Run(phase, func(t *testing.T) {
			c, s, body := fixture(t)
			switch phase {
			case "ip":
				s.b.failAt = 1
			case "challenge":
				s.b.failAt = 2
			case "source":
				s.sourceErr = identity.ForbiddenError{}
			}
			h, err := emailhttp.NewConfirmationHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(body))
			want := 503
			if phase == "source" {
				want = 403
			}
			if w.Code != want || s.calls != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("failed admission executed mutation", w.Code)
			}
			if phase == "ip" && s.sources != 0 {
				t.Fatal("source work preceded IP admission")
			}
		})
	}
}
func (s *owner) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	s.calls++
	s.last = r
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil || len(s.b.requests) != 2 || len(s.b.requests[1].Requests) != 2 || s.b.requests[1].Requests[1].Policy.Period() != time.Hour {
		s.t.Error("wrong protected input or original budget")
	}
	if s.result != nil {
		return s.result(r)
	}
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: "original-user", RecordID: "original-address", ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.email.verification-confirm"}
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		s.t.Fatal(err)
	}
	return email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Replayed: true}, nil
}

func fixture(t *testing.T) (emailhttp.ConfirmationConfig, *owner, string) {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	b := &backend{}
	rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: b, Namespace: "confirmation-test", Key: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	s := &owner{t: t, b: b}
	signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "https://tenant.example", Audiences: []string{"verification"}, Subject: "original-user", Resource: "original-address", Operation: "identity.identifier.verify", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: "original-issued-grant", Tenant: "tenant-a", MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"token": token, "callback": "https://tenant.example/finish", "commandID": string(id)})
	return emailhttp.ConfirmationConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: s, Rate: rate, Origin: "https://tenant.example", ActorID: "confirmation-entry", PolicyRevision: 9, Now: func() time.Time { return now }, MaximumDuration: time.Second}, s, string(data)
}
func request(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/email/verification-confirm", strings.NewReader(body))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-not-authority"})
	return r
}
func TestConfirmationPreservesOriginalAdmissionAndReplay(t *testing.T) {
	c, s, body := fixture(t)
	h, err := emailhttp.NewConfirmationHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || s.sources != 1 || s.calls != 1 || s.last.TenantID != "tenant-a" || s.last.Network != "198.51.100.7" || !strings.Contains(w.Body.String(), `"replayed":true`) || strings.Contains(w.Body.String(), "original-issued-grant") || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("original replay/custody not preserved", w.Code)
	}
}
