package otphttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
)

type recoveryOwner struct {
	t      *testing.T
	calls  int
	result otp.SigninResult
	err    error
	invoke func(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error)
}

func (o *recoveryOwner) RecoverSignin(ctx context.Context, r otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	o.calls++
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil || r.TenantID != "tenant-a" || r.UserID != "" || r.Caller.Request.Action != "identity.otp.signin" {
		o.t.Error("invalid or unbounded original recovery")
	}
	if o.invoke != nil {
		return o.invoke(ctx, r)
	}
	return o.result, o.err
}

func recoveryFixture(t *testing.T) (otphttp.SigninRecoveryConfig, *recoveryOwner, string, otp.SigninResult) {
	t.Helper()
	c, _, original := fixture(t)
	c.Network.Limits.MaximumFields = 64
	var input struct {
		SendCommandID identity.CommandID `json:"sendCommandID"`
	}
	if json.Unmarshal([]byte(original), &input) != nil {
		t.Fatal("fixture")
	}
	result := issuance(t, c, otp.SigninRequest{TenantID: "tenant-a", SendCommandID: input.SendCommandID})
	result.Issuance.Replayed = true
	b, _ := result.Recovery.Bindings()
	projection := otphttp.SigninRecovery{SendCommandID: b.SendCommandID, Attempt: otphttp.SigninAttempt{CommandID: b.Attempt.CommandID, TenantID: b.Attempt.TenantID, AttemptID: string(b.Attempt.AttemptID), Fingerprint: string(b.Attempt.Fingerprint), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion}, ExpectedVersion: b.ExpectedVersion, DigestKeyVersion: b.DigestKeyVersion, ScopeDigest: b.ScopeDigest}
	body, _ := json.Marshal(map[string]any{"flowID": "AQEBAQEBAQEBAQEBAQEBAQ", "recovery": projection})
	owner := &recoveryOwner{t: t, result: result}
	return otphttp.SigninRecoveryConfig{Network: c.Network, Service: owner, Rate: c.Rate, Origin: c.Origin, FlowCookie: c.FlowCookie, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, MaximumDuration: c.MaximumDuration}, owner, string(body), result
}

func recoveryRequest(body string) *http.Request {
	r := request(body)
	r.URL.Path = "/v1/otp/signin/recover"
	r.RequestURI = r.URL.RequestURI()
	return r
}

func TestSigninRecoveryReturnsHistoryWithoutCredentialDelivery(t *testing.T) {
	c, owner, body, result := recoveryFixture(t)
	b, _ := result.Recovery.Bindings()
	h, err := otphttp.NewSigninRecoveryHandler(c)
	if err != nil || owner.calls != 0 {
		t.Fatal("construction invokes recovery")
	}
	for _, unavailable := range []bool{false, true} {
		if unavailable {
			owner.result.Issuance.CommitOutcome = identity.CommitOutcomeUnknown
			owner.result.SessionID = ""
			owner.err = errors.New("private recovery diagnostic")
		}
		r := recoveryRequest(body)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 200
		if unavailable {
			want = 503
		}
		var out otphttp.SigninResponse
		if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SignedIn || out.Recovery == nil || out.CommandID != b.Attempt.CommandID || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("unsafe recovery status=%d", w.Code)
		}
		if !unavailable && (out.CommitOutcome != "committed" || out.SessionID != result.SessionID) {
			t.Fatal("history lost")
		}
		if unavailable && out.CommitOutcome != "unknown" {
			t.Fatal("ambiguity erased")
		}
	}
	if owner.calls != 2 {
		t.Fatal("recovery was retried")
	}
	if _, err := result.Issuance.Token.Reveal(); err != nil {
		t.Fatal("recovery consumed bearer")
	}
	if _, err := result.CSRFToken.Reveal(); err != nil {
		t.Fatal("recovery consumed csrf")
	}
}

func TestSigninRecoveryClosedOriginalInputAndAdmission(t *testing.T) {
	for _, mode := range []string{"code", "identity", "nested", "case", "duplicate", "digest-string", "digest-short", "digest-null", "tenant", "origin", "cookie", "authorization", "key", "query", "trailer", "http", "method", "host"} {
		t.Run(mode, func(t *testing.T) {
			c, o, body, _ := recoveryFixture(t)
			var j map[string]any
			json.Unmarshal([]byte(body), &j)
			recovery := j["recovery"].(map[string]any)
			switch mode {
			case "code":
				j["code"] = "123456"
			case "identity":
				j["userID"] = "replacement"
			case "nested":
				recovery["replacement"] = true
			case "case":
				j["FlowID"] = j["flowID"]
				delete(j, "flowID")
			case "digest-string":
				recovery["scopeDigest"] = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			case "digest-short":
				recovery["scopeDigest"] = []int{1}
			case "digest-null":
				recovery["scopeDigest"].([]any)[1] = nil
			case "tenant":
				recovery["attempt"].(map[string]any)["tenantID"] = "tenant-b"
			}
			data, _ := json.Marshal(j)
			body = string(data)
			if mode == "duplicate" {
				body = strings.Replace(body, `"flowID":`, `"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","flowID":`, 1)
			}
			r := recoveryRequest(body)
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "cookie":
				r.Header.Del("Cookie")
			case "authorization":
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
			case "key":
				r.Header.Set("Idempotency-Key", "replacement")
			case "query":
				r.URL.RawQuery = "code=123456"
			case "trailer":
				r.Trailer = http.Header{"Code": []string{"123456"}}
			case "http":
				r.TLS = nil
			case "method":
				r.Method = http.MethodGet
			case "host":
				r.Host = "foreign.example"
			}
			h, err := otphttp.NewSigninRecoveryHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || o.calls != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("unsafe input reached recovery mode=%s status=%d", mode, w.Code)
			}
		})
	}
}

func TestSigninRecoverySharedIPBudgetBoundsNativeReads(t *testing.T) {
	c, o, body, _ := recoveryFixture(t)
	h, err := otphttp.NewSigninRecoveryHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, recoveryRequest(body))
		want := 200
		if i == 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("wrong shared admission status=%d", w.Code)
		}
		if i == 20 {
			retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
			if err != nil || retry <= 0 || o.calls != 20 {
				t.Fatal("native reads unbounded or backoff lost")
			}
		}
	}
}

func FuzzSigninRecoveryClosedInput(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","recovery":null}`)
	f.Add(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","flowID":"duplicate"}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		c, _, _, _ := recoveryFixture(t)
		h, err := otphttp.NewSigninRecoveryHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, recoveryRequest(body))
		if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile recovery escaped response custody")
		}
	})
}

func TestSigninRecoveryCannotDiscloseForeignOrRetryFailure(t *testing.T) {
	for _, mode := range []string{"foreign-command", "foreign-recovery", "fresh", "panic", "cancel", "session-control", "session-length", "not-committed"} {
		t.Run(mode, func(t *testing.T) {
			c, o, body, result := recoveryFixture(t)
			r := recoveryRequest(body)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			o.invoke = func(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error) {
				switch mode {
				case "foreign-command":
					result.Issuance.CommandID, _ = identity.NewCommandID()
				case "foreign-recovery":
					result.Recovery = otp.SigninRecovery{}
				case "fresh":
					result.Issuance.Replayed = false
				case "panic":
					panic("private")
				case "cancel":
					cancel()
				case "session-control":
					result.SessionID = "session\nprivate"
				case "session-length":
					result.SessionID = strings.Repeat("a", 129)
				case "not-committed":
					result.Issuance.CommitOutcome = identity.CommitOutcomeNotCommitted
					result.SessionID = ""
				}
				return result, nil
			}
			h, err := otphttp.NewSigninRecoveryHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 503
			if mode == "not-committed" {
				want = 200
			}
			var out otphttp.SigninResponse
			json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != want || o.calls != 1 || out.SignedIn || out.SessionID != "" || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("unsafe failure or retry")
			}
			if strings.HasPrefix(mode, "foreign") && (out.CommandID != "" || out.Recovery != nil) {
				t.Fatal("foreign history disclosed")
			}
		})
	}
}

func TestSigninRecoveryTypedHooksCannotDeliverCredentials(t *testing.T) {
	c, o, body, _ := recoveryFixture(t)
	observed := false
	middleware := hook(identityhttp.MiddlewareAfterHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		s, ok := identityhttp.PipelineValue[otphttp.SigninRecoveryState](r)
		out, attempted := s.Attempt()
		observed = ok && attempted && out.CommitOutcome == "committed" && !out.SignedIn
		w.Header().Set("Set-Cookie", "forged=credential")
		w.Header().Set("Trailer:X-CSRF-Token", "forged")
		next.ServeHTTP(w, r)
	})
	h, err := otphttp.NewSigninRecoveryHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{middleware})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, recoveryRequest(body))
	if w.Code != 200 || !observed || o.calls != 1 || len(w.Result().Cookies()) != 0 || w.Header().Get("Trailer:X-CSRF-Token") != "" {
		t.Fatal("hook escaped recovery custody")
	}
}
