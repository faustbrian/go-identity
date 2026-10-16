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
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// The public source seam denies custody; malformed or structurally valid input
// must never turn its denial into executable workflow or credential delivery.
// Real native/HTTPS success and transaction effects are tested in reference.
type deniedEmailVerificationOwner struct{ mutations int }

// This parser fixture does not claim native rate atomicity. The explicit port
// admits budgets so that source custody, rather than a rate outage, denies input.
type emailVerificationFuzzRate struct{ *shared }

func (*emailVerificationFuzzRate) AdmitAtomicStrict(_ context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for n, request := range r.Requests {
		out.Decisions[n] = ratelimit.Decision{Allowed: true, Remaining: request.Policy.Limit() - request.Cost, Limit: request.Policy.Limit(), Reset: request.Now.Add(request.Policy.Period()), Reason: ratelimit.ReasonAllowed}
	}
	return out, nil
}

func (o *deniedEmailVerificationOwner) SendEmailVerification(context.Context, otp.EmailVerificationSendRequest) (otp.SendResult, error) {
	o.mutations++
	return otp.SendResult{}, identity.ForbiddenError{}
}
func (o *deniedEmailVerificationOwner) EmailVerify(context.Context, otp.EmailVerifyRequest) (otp.EmailVerifyResult, error) {
	o.mutations++
	return otp.EmailVerifyResult{}, identity.ForbiddenError{}
}
func (o *deniedEmailVerificationOwner) RecoverEmailVerify(context.Context, otp.EmailVerifyRecoveryRequest) (otp.EmailVerifyResult, error) {
	o.mutations++
	return otp.EmailVerifyResult{}, identity.ForbiddenError{}
}
func (*deniedEmailVerificationOwner) EmailVerificationSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error) {
	return session.Session{}, identity.ForbiddenError{}
}
func (*deniedEmailVerificationOwner) EmailVerificationSendDestination(context.Context, otp.EmailVerificationSendRequest) (otp.DestinationInput, error) {
	return otp.DestinationInput{}, identity.ForbiddenError{}
}
func (*deniedEmailVerificationOwner) EmailVerificationChallenge(context.Context, otp.EmailVerifyRequest) (otp.EmailVerificationChallenge, error) {
	return otp.EmailVerificationChallenge{}, identity.ForbiddenError{}
}

func FuzzEmailVerificationClosedInput(f *testing.F) {
	for _, body := range []string{`{}`, `null`, `{"flowID":null}`, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456"}`, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","flowID":"duplicate"}`, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","recovery":null}`} {
		f.Add(body, false)
		f.Add(body, true)
	}
	f.Fuzz(func(t *testing.T, body string, recovery bool) {
		if len(body) > 4096 {
			t.Skip()
		}
		base, rateOwner, _ := fixture(t)
		rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: &emailVerificationFuzzRate{&shared{rateOwner.backend}}, Namespace: "email-verification-fuzz", Key: [32]byte{1}, Now: base.Now, MaximumDuration: base.MaximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rate.Close() })
		key, err := session.NewCSRFKey(1, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		source := &deniedEmailVerificationOwner{}
		c := otphttp.EmailVerificationConfig{Network: base.Network, Service: source, Source: source, Cookie: base.SessionCookie, Origin: base.Origin, CSRFKeys: []session.CSRFKey{key}, VerificationRate: rate, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
		factory, path := otphttp.NewEmailVerifyHandler, "/v1/otp/email-verify"
		if recovery {
			factory, path = otphttp.NewEmailVerifyRecoveryHandler, "/v1/otp/email-verify/recover"
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
		if w.Code < 400 || source.mutations != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile input bypassed denied custody or response safety")
		}
	})
}
