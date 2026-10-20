package phonehttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// These owners are deliberate transport seams, not native reset evidence.
// The separate PostgreSQL/reference journey proves real authority and effects.
type resetTransportOwner struct {
	events             []string
	riskErr, nativeErr error
	result             phone.PasswordResetCompleteResult
	request            phone.PasswordResetRequestRequestSpec
	complete           phone.PasswordResetCompleteRequestSpec
	now                time.Time
	panicRisk          bool
}

func (o *resetTransportOwner) evidence(purpose string) (risk.PhoneEvidenceResult, error) {
	if o.panicRisk {
		panic("private-provider-details")
	}
	if o.riskErr != nil {
		return risk.PhoneEvidenceResult{}, o.riskErr
	}
	ref, _ := risk.ParseRiskEvidenceRef("re1.1." + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43))
	return risk.PhoneEvidenceResult{Outcome: risk.EvidenceCommitted, Evidence: risk.RiskEvidence{Reference: ref, Purpose: purpose, IssuedAt: o.now, ExpiresAt: o.now.Add(time.Minute), MaxUses: 1}}, nil
}
func (o *resetTransportOwner) EvaluatePasswordResetRequestRisk(ctx context.Context, r phone.PasswordResetInitiationRiskRequest) (risk.PhoneEvidenceResult, error) {
	o.events = append(o.events, "request-risk")
	if _, err := r.Bindings(); err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	return o.evidence("phone-password-reset-initiate")
}
func (o *resetTransportOwner) EvaluatePasswordResetCompletionRisk(ctx context.Context, r phone.PasswordResetCompletionRiskRequest) (risk.PhoneEvidenceResult, error) {
	o.events = append(o.events, "complete-risk")
	if _, err := r.Bindings(); err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	return o.evidence("phone-password-reset-complete")
}
func (o *resetTransportOwner) PasswordResetRequest(_ context.Context, r phone.PasswordResetRequestRequest) (phone.PasswordResetRequestResult, error) {
	o.events = append(o.events, "request")
	var err error
	o.request, err = r.Bindings()
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	return phone.PasswordResetRequestResult{}, o.nativeErr
}
func (o *resetTransportOwner) PasswordResetComplete(_ context.Context, r phone.PasswordResetCompleteRequest) (phone.PasswordResetCompleteResult, error) {
	o.events = append(o.events, "complete")
	var err error
	o.complete, err = r.Bindings()
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	if o.result.Outcome != identity.CommitOutcomeInvalid {
		return o.result, o.nativeErr
	}
	return phone.PasswordResetCompleteResult{CommandID: o.complete.CommandID, Outcome: identity.CommitOutcomeCommitted, CredentialVersion: 2, SessionsRevoked: true}, o.nativeErr
}
func (*resetTransportOwner) RecoverPasswordResetRequest(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (phone.PasswordResetRequestResult, error) {
	return phone.PasswordResetRequestResult{}, identity.ForbiddenError{}
}
func (*resetTransportOwner) RecoverPasswordResetComplete(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (phone.PasswordResetCompleteResult, error) {
	return phone.PasswordResetCompleteResult{}, identity.ForbiddenError{}
}
func (o *resetTransportOwner) PasswordResetCompletionRateSource(_ context.Context, _ capability.Proof, _ otp.SendFlow, c authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	o.events = append(o.events, "source")
	if c.Request.Subject.Kind != authorization.SubjectServiceAccount || c.Request.Action != "identity.phone.password-reset-complete" || c.Request.Resource.Type != "identity.user" || c.Request.Resource.ID != "" {
		return "", "", "", 0, identity.ForbiddenError{}
	}
	return "AQEBAQEBAQEBAQEBAQEBAQ", "AgICAgICAgICAgICAgICAg", "AwMDAwMDAwMDAwMDAwMDAw", time.Minute, nil
}

func resetTransportFixture(t *testing.T) (phonehttp.PasswordResetConfig, *resetTransportOwner, *http.Request) {
	t.Helper()
	base, _ := fixture(t)
	const tenant identity.TenantID = "AQEBAQEBAQEBAQEBAQEBAQ"
	base.Network.TenantHosts[0].TenantID = tenant
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deviceConfig := session.BrowserDeviceConfig{Namespace: "phone-reset-transport", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(t.Context(), base.Now(), tenant, string(base.Origin))
	if err != nil {
		t.Fatal(err)
	}
	deviceResponse := http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	o := &resetTransportOwner{now: base.Now()}
	c := phonehttp.PasswordResetConfig{Network: base.Network, Service: o, Risk: o, Source: o, NumberPolicy: base.NumberPolicy, DeliveryRate: base.DeliveryRate, CompletionRate: base.VerificationRate, Cookie: flowCookie, Origin: base.Origin, Device: deviceConfig, ActorID: "phone-reset-service", PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
	r := request(`{"commandID":"AgICAgICAgICAgICAgICAg","riskIssuanceCommandID":"AwMDAwMDAwMDAwMDAwMDAw","flowID":"BAQEBAQEBAQEBAQEBAQEBA","number":"+12025550123"}`)
	r.URL.Path = "/v1/phone/password-reset-request"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("X-CSRF-Token")
	r.Header.Del("Cookie")
	r.Header.Set("Idempotency-Key", "same-logical-recovery")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	r.AddCookie(deviceResponse.Cookies()[0])
	return c, o, r
}

func TestPasswordResetRequestTransportDoesNotEnumerate(t *testing.T) {
	var baseline string
	for _, mode := range []string{"queued", "ineligible", "provider-unavailable", "provider-panic", "native-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			c, o, r := resetTransportFixture(t)
			switch mode {
			case "ineligible":
				o.riskErr = identity.ForbiddenError{}
			case "provider-unavailable":
				o.riskErr = identity.UnavailableError{}
			case "provider-panic":
				o.panicRisk = true
			case "native-unavailable":
				o.nativeErr = identity.UnavailableError{}
			}
			h, err := phonehttp.NewPasswordResetRequestHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 202 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("request did not give uniform credential-free acknowledgment", w.Code)
			}
			if baseline == "" {
				baseline = w.Body.String()
			} else if baseline != w.Body.String() {
				t.Fatal("request exposed account/provider eligibility")
			}
			var out map[string]any
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 2 || out["accepted"] != true || out["commandID"] != "AgICAgICAgICAgICAgICAg" {
				t.Fatal("acknowledgment claimed private commitment or exposed authority")
			}
			if o.riskErr != nil || o.panicRisk {
				if !slices.Equal(o.events, []string{"request-risk"}) {
					t.Fatal("risk denial reached request")
				}
			} else if !slices.Equal(o.events, []string{"request-risk", "request"}) {
				t.Fatal("request skipped owned risk")
			}
		})
	}
}

func TestPasswordResetTransportRejectsAlternateAuthority(t *testing.T) {
	for _, mode := range []string{"origin", "bearer", "csrf", "key", "query", "body-override", "duplicate-body", "missing-flow", "missing-device"} {
		t.Run(mode, func(t *testing.T) {
			c, o, r := resetTransportFixture(t)
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "bearer":
				r.Header.Set("Authorization", "Bearer ignored")
			case "csrf":
				r.Header.Set("X-CSRF-Token", "override")
			case "key":
				r.Header.Del("Idempotency-Key")
			case "query":
				r.URL.RawQuery = "userID=override"
			case "body-override", "duplicate-body":
				var body bytes.Buffer
				_, _ = body.ReadFrom(r.Body)
				value := strings.TrimSuffix(body.String(), "}")
				if mode == "body-override" {
					value += `,"userID":"override"}`
				} else {
					value += `,"number":"+12025550123"}`
				}
				r.Body = http.NoBody
				r = replaceResetBody(r, value)
			case "missing-flow", "missing-device":
				cookies := r.Cookies()
				r.Header.Del("Cookie")
				for _, cookie := range cookies {
					if mode == "missing-flow" && cookie.Name == "__Host-identity_flow" || mode == "missing-device" && cookie.Name == "__Host-identity_device" {
						continue
					}
					r.AddCookie(cookie)
				}
			}
			h, err := phonehttp.NewPasswordResetRequestHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || len(o.events) != 0 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("alternate input reached native authority", w.Code)
			}
		})
	}
}

func replaceResetBody(r *http.Request, value string) *http.Request {
	r.Body = ioResetBody{strings.NewReader(value)}
	r.ContentLength = int64(len(value))
	return r
}

type ioResetBody struct{ *strings.Reader }

func (ioResetBody) Close() error { return nil }

func resetCompleteTransportRequest(t *testing.T, r *http.Request, now time.Time) *http.Request {
	t.Helper()
	signer, err := capability.NewHMACSHA256Signer("transport-only", bytes.Repeat([]byte{62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "https://tenant.example", Audiences: []string{"reset"}, Subject: "transport-only", Tenant: "AQEBAQEBAQEBAQEBAQEBAQ", Resource: "identity.password/transport-only", Operation: "identity.phone.password-reset-complete", ID: "transport-only-grant", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"commandID": "AgICAgICAgICAgICAgICAg", "riskIssuanceCommandID": "AwMDAwMDAwMDAwMDAwMDAw", "flowID": "BAQEBAQEBAQEBAQEBAQEBA", "token": token, "phoneCode": "123456", "totpCode": "654321", "newPassword": "transport-only replacement"})
	r.URL.Path = "/v1/phone/password-reset-complete"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Idempotency-Key")
	return replaceResetBody(r, string(body))
}

func TestPasswordResetCompletionTransportUsesOwnedConjunction(t *testing.T) {
	c, o, r := resetTransportFixture(t)
	r = resetCompleteTransportRequest(t, r, c.Now())
	h, err := phonehttp.NewPasswordResetCompleteHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !slices.Equal(o.events, []string{"source", "complete-risk", "complete"}) {
		t.Fatal("completion skipped source, distinct risk or workflow", w.Code, o.events)
	}
	if o.complete.NewPassword.Len() != 0 || o.complete.ResetCapability.ValidateBounds(32, 4096) == nil {
		t.Fatal("transport retained live password/capability custody")
	}
	for _, sensitive := range []string{"transport-only replacement", "123456", "654321", "re1.", "transport-only-grant"} {
		if strings.Contains(w.Body.String(), sensitive) {
			t.Fatal("completion disclosed submitted custody")
		}
	}
	if w.Header().Get("Set-Cookie") != "" || !strings.Contains(w.Body.String(), `"sessionsRevoked":true`) {
		t.Fatal("completion signed in or lost required effects")
	}
}

func TestPasswordResetCompletionDelegatesHistoricalEvidenceToNativeOwner(t *testing.T) {
	c, o, r := resetTransportFixture(t)
	r = resetCompleteTransportRequest(t, r, c.Now())
	// Only the native workflow distinguishes a new mutation (fresh evidence
	// required) from an exact terminal receipt replay (no renewed validity).
	o.now = c.Now().Add(-2 * time.Minute)
	h, err := phonehttp.NewPasswordResetCompleteHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !slices.Equal(o.events, []string{"source", "complete-risk", "complete"}) {
		t.Fatal("transport replaced native historical authority with current-time admission", w.Code)
	}
}

func TestPasswordResetCompletionPreservesUnknownAndRejectsKeys(t *testing.T) {
	for _, mode := range []string{"unknown", "committed-error", "key", "risk-denied"} {
		t.Run(mode, func(t *testing.T) {
			c, o, r := resetTransportFixture(t)
			r = resetCompleteTransportRequest(t, r, c.Now())
			switch mode {
			case "unknown":
				o.result = phone.PasswordResetCompleteResult{CommandID: "AgICAgICAgICAgICAgICAg", Outcome: identity.CommitOutcomeUnknown}
				o.nativeErr = identity.UnavailableError{}
			case "committed-error":
				o.nativeErr = errors.New("private-provider-details")
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
			case "risk-denied":
				o.riskErr = identity.ForbiddenError{}
			}
			h, err := phonehttp.NewPasswordResetCompleteHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), `"completed":true`) || strings.Contains(w.Body.String(), `"sessionsRevoked":true`) || strings.Contains(w.Body.String(), "private-provider-details") {
				t.Fatal("failure claimed success or exposed native error", w.Code)
			}
			if mode == "key" && len(o.events) != 0 {
				t.Fatal("forbidden retry key reached owners")
			}
			if mode == "unknown" && !strings.Contains(w.Body.String(), `"commitOutcome":"unknown"`) {
				t.Fatal("unknown was changed into rollback")
			}
		})
	}
}

func TestPasswordResetCompletionRejectsTransportOverridesBeforeSource(t *testing.T) {
	for _, mode := range []string{"get", "origin", "bearer", "remember", "duplicate-code", "cookie", "rate-closed"} {
		t.Run(mode, func(t *testing.T) {
			c, o, r := resetTransportFixture(t)
			r = resetCompleteTransportRequest(t, r, c.Now())
			h, err := phonehttp.NewPasswordResetCompleteHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "get":
				r.Method = http.MethodGet
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "bearer":
				r.Header.Set("Authorization", "Bearer override")
			case "cookie":
				r.Header.Del("Cookie")
			case "rate-closed":
				_ = c.CompletionRate.Close()
			case "remember", "duplicate-code":
				var body bytes.Buffer
				_, _ = body.ReadFrom(r.Body)
				value := strings.TrimSuffix(body.String(), "}")
				if mode == "remember" {
					value += `,"remember":false}`
				} else {
					value += `,"phoneCode":"654321"}`
				}
				r = replaceResetBody(r, value)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || len(o.events) != 0 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("transport override reached original-source or risk authority", mode, w.Code)
			}
		})
	}
}

func FuzzPasswordResetRequestBody(f *testing.F) {
	f.Add(`{"commandID":"AgICAgICAgICAgICAgICAg","riskIssuanceCommandID":"AwMDAwMDAwMDAwMDAwMDAw","flowID":"BAQEBAQEBAQEBAQEBAQEBA","number":"+12025550123"}`)
	f.Add(`{"number":"+12025550123","number":"override"}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		c, o, r := resetTransportFixture(t)
		h, err := phonehttp.NewPasswordResetRequestHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, replaceResetBody(r, body))
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile body escaped no-session response")
		}
		if w.Code != 202 && len(o.events) != 0 {
			t.Fatal("rejected body reached native attempt")
		}
		if w.Code != 202 && w.Code != 400 && w.Code != 403 && w.Code != 429 && w.Code != 503 {
			t.Fatal("unexpected body failure status", w.Code)
		}
	})
}
