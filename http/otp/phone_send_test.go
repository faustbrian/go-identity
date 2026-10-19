package otphttp_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneSigninSendPreservesCanonicalNativeScope(t *testing.T) {
	for _, mode := range []string{"phone", "extra-user", "invalid-number", "missing-key", "missing-device", "email-path", "foreign-origin", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			base, generic, r := sendFixture(t)
			policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US"})
			if err != nil {
				t.Fatal(err)
			}
			owner := &phoneSigninOwner{t: t, send: generic.result}
			if mode == "unknown" {
				owner.send.Outcome = identity.CommitOutcomeUnknown
			}
			body := `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"2025550123"}`
			if mode == "extra-user" {
				body = strings.TrimSuffix(body, "}") + `,"userID":"replacement"}`
			}
			if mode == "invalid-number" {
				body = strings.ReplaceAll(body, "2025550123", "not-a-number")
			}
			r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
			r.URL.Path = "/v1/phone/send-signin"
			if mode == "email-path" {
				r.URL.Path = "/v1/otp/send"
			}
			r.RequestURI = r.URL.RequestURI()
			if mode == "missing-key" {
				r.Header.Del("Idempotency-Key")
			}
			if mode == "missing-device" {
				cookies := r.Cookies()
				r.Header.Del("Cookie")
				for _, cookie := range cookies {
					if cookie.Name != "__Host-identity_device" {
						r.AddCookie(cookie)
					}
				}
			}
			if mode == "foreign-origin" {
				r.Header.Set("Origin", "https://foreign.example")
			}
			h, err := otphttp.NewPhoneSigninSendHandler(otphttp.PhoneSigninSendConfig{Network: base.Network, Service: owner, Policy: policy, Rate: base.Rate, Origin: base.Origin, FlowCookie: base.FlowCookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration})
			if err != nil || owner.sends != 0 {
				t.Fatal("phone send construction invoked native work", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "+12025550123") {
				t.Fatal("phone send exposed credentials or recipient")
			}
			if mode == "phone" || mode == "unknown" {
				want := 202
				if mode == "unknown" {
					want = 503
				}
				number, err := owner.lastSend.Number.Record()
				if w.Code != want || owner.sends != 1 || err != nil || number.E164 != "+12025550123" || owner.lastSend.TenantID != "tenant-a" || owner.lastSend.Network != "198.51.100.7" || owner.lastSend.Device == "" || owner.attempts != 0 {
					t.Fatal("phone send changed canonical scope, retried or consumed a code", w.Code, err)
				}
			} else if w.Code < 400 || owner.sends != 0 {
				t.Fatal("invalid phone initiation reached native work", w.Code)
			}
		})
	}
}

func FuzzPhoneSigninSendClosedInput(f *testing.F) {
	for _, seed := range []string{`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"2025550123"}`, `{"number":"+12025550123","number":"replacement"}`, `{"flowID":null,"number":"+12025550123"}`, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"+12025550123","userID":"replacement"}`, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"２０２５５５０１２３"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		base, generic, r := sendFixture(t)
		policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US"})
		if err != nil {
			t.Fatal(err)
		}
		owner := &phoneSigninOwner{t: t, send: generic.result}
		h, err := otphttp.NewPhoneSigninSendHandler(otphttp.PhoneSigninSendConfig{Network: base.Network, Service: owner, Policy: policy, Rate: base.Rate, Origin: base.Origin, FlowCookie: base.FlowCookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = "/v1/phone/send-signin"
		r.RequestURI = r.URL.RequestURI()
		r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || owner.attempts != 0 || owner.sends > 1 {
			t.Fatal("hostile issuance input disclosed credentials, consumed a code or retried")
		}
		if owner.sends == 1 {
			number, err := owner.lastSend.Number.Record()
			if err != nil || number.Profile != phone.CurrentNumberProfile() || owner.lastSend.TenantID != "tenant-a" || owner.lastSend.Network != "198.51.100.7" || owner.lastSend.Device == "" {
				t.Fatal("accepted hostile input replaced trusted admission scope")
			}
		}
	})
}
