package otphttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

type deniedEmailChangeOwner struct{ mutations int }

func (o *deniedEmailChangeOwner) EmailChangeRequest(context.Context, otp.EmailChangeRequest) (otp.SendResult, error) {
	o.mutations++
	return otp.SendResult{}, identity.ForbiddenError{}
}
func (o *deniedEmailChangeOwner) EmailChangeConfirm(context.Context, otp.EmailChangeConfirmRequest) (otp.EmailChangeResult, error) {
	o.mutations++
	return otp.EmailChangeResult{}, identity.ForbiddenError{}
}
func (o *deniedEmailChangeOwner) RecoverEmailChange(context.Context, otp.EmailChangeRecoveryRequest) (otp.EmailChangeResult, error) {
	o.mutations++
	return otp.EmailChangeResult{}, identity.ForbiddenError{}
}
func (*deniedEmailChangeOwner) EmailChangeSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error) {
	return session.Session{}, identity.ForbiddenError{}
}
func (*deniedEmailChangeOwner) EmailChangeSendDestination(context.Context, otp.EmailChangeRequest) (otp.DestinationInput, error) {
	return otp.DestinationInput{}, identity.ForbiddenError{}
}
func (*deniedEmailChangeOwner) EmailChangeChallenge(context.Context, otp.EmailChangeConfirmRequest) (otp.EmailChangeChallenge, error) {
	return otp.EmailChangeChallenge{}, identity.ForbiddenError{}
}

func FuzzEmailChangeClosedInput(f *testing.F) {
	for _, body := range []string{`{}`, `null`, `{"flowID":null}`, `{"flowID":"original","originCommandID":"AQEBAQEBAQEBAQEBAQEBAQ","addressID":"pending"}`, `{"flowID":"original","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456"}`, `{"flowID":"a","flowID":"b"}`, `{"flowID":"original","recovery":null}`} {
		for mode := range 3 {
			f.Add(body, mode)
		}
	}
	f.Fuzz(func(t *testing.T, body string, mode int) {
		if len(body) > 4096 || mode < 0 || mode > 2 {
			t.Skip()
		}
		base, rateOwner, _ := fixture(t)
		backend := &emailVerificationFuzzRate{&shared{rateOwner.backend}}
		verification, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "email-change-fuzz", Key: [32]byte{1}, Now: base.Now, MaximumDuration: base.MaximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = verification.Close() })
		key, err := session.NewCSRFKey(1, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		owner := &deniedEmailChangeOwner{}
		c := otphttp.EmailChangeConfig{Network: base.Network, Service: owner, Source: owner, Cookie: base.SessionCookie, Origin: base.Origin, CSRFKeys: []session.CSRFKey{key}, VerificationRate: verification, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
		factory, path := otphttp.NewEmailChangeConfirmHandler, "/v1/otp/email-change-confirm"
		if mode == 0 {
			requestRate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "email-change-fuzz", Key: [32]byte{1}, Now: base.Now, MaximumDuration: base.MaximumDuration})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = requestRate.Close() })
			device, _, _ := sendFixture(t)
			c.RequestRate, c.Device = requestRate, device.Device
			factory, path = otphttp.NewEmailChangeRequestHandler, "/v1/otp/email-change-request"
		}
		if mode == 2 {
			factory, path = otphttp.NewEmailChangeRecoveryHandler, "/v1/otp/email-change-confirm/recover"
		}
		h, err := factory(c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(body)
		r.URL.Path = path
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
		r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.mutations != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile change input bypassed original custody or leaked credentials")
		}
	})
}
