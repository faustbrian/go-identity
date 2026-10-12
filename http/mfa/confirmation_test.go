package mfahttp

import (
	"context"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfirmationHTTPRequiresNativeCookieComposition(t *testing.T) {
	if h, err := NewEnrollmentConfirmationHandler(EnrollmentConfirmationConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured confirmation acquired mutation authority")
	}
}

func TestConfirmationFeatureRejectsMissingNativeOwners(t *testing.T) {
	if _, err := NewFeature(FeatureConfig{EnrollmentConfirmation: &EnrollmentConfirmationConfig{}}); err == nil {
		t.Fatal("missing native confirmation exposed shared verify operation")
	}
}

type confirmationOwner struct {
	reads, calls int
	until        time.Time
	result       mfa.TotpVerifyResult
	err          error
	last         mfa.TotpVerifyRequest
	after        func()
}

func (o *confirmationOwner) EnrollmentConfirmationRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (time.Duration, time.Time, error) {
	o.reads++
	o.last = r
	if r.Validate() != nil {
		panic("invalid native confirmation custody")
	}
	return time.Minute, o.until, nil
}
func (o *confirmationOwner) TotpVerify(ctx context.Context, r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	o.calls++
	o.last = r
	if r.Validate() != nil {
		panic("invalid protected confirmation")
	}
	if o.after != nil {
		o.after()
	}
	return o.result, o.err
}
func (*confirmationOwner) RecoverTotpVerify(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.TotpVerifyResult, error) {
	return mfa.TotpVerifyResult{}, identity.UnavailableError{}
}

func TestConfirmationHTTPUsesClosedEnrollmentVariantAndNoSessionDelivery(t *testing.T) {
	for _, mode := range []string{"success", "unknown", "denied", "expired", "missing-variant", "duplicate-variant", "login-fields"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, clock, r := uriFixture(t)
			factor, _ := identity.NewCommandID()
			command, _ := identity.NewCommandID()
			owner := &confirmationOwner{until: clock.now.Add(10 * time.Second), result: mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Enrollment: mfa.Enrollment{ID: mfa.EnrollmentID(factor), FactorMethod: "totp", Version: 2}}}
			rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: &strictRate{}, Namespace: "confirmation-test", Key: [32]byte{2}, Now: clock.Now, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { rate.Close() })
			config := EnrollmentConfirmationConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
			r.URL.Path = "/v1/mfa/totp-verify"
			r.RequestURI = r.URL.RequestURI()
			r.Header.Set("X-MFA-Variant", "enrollment")
			body := `{"commandID":"` + string(command) + `","factorID":"` + string(factor) + `","code":"123456"}`
			switch mode {
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "denied":
				owner.err = identity.ForbiddenError{}
			case "expired":
				owner.after = func() { clock.now = owner.until }
			case "missing-variant":
				r.Header.Del("X-MFA-Variant")
			case "duplicate-variant":
				r.Header["X-MFA-Variant"] = []string{"enrollment", "enrollment"}
			case "login-fields":
				body = strings.TrimSuffix(body, "}") + `,"challengeID":"foreign"}`
			}
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			h, err := NewEnrollmentConfirmationHandler(config)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("confirmation issued session or cacheable output")
			}
			if mode == "success" {
				if w.Code != 200 || owner.calls != 1 || owner.last.Enrollment == nil || !strings.Contains(w.Body.String(), `"activated":true`) {
					t.Fatal("native activation not delivered", w.Code)
				}
				for _, combined := range []bool{false, true} {
					selection := FeatureConfig{EnrollmentConfirmation: &config}
					if combined {
						login, _, _, _ := handlerFixture(t)
						selection.TOTPVerify = &login
					}
					feature, err := NewFeature(selection)
					if err != nil {
						t.Fatal("confirmation feature rejected", err)
					}
					ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
					if err != nil || len(ops) != 1 {
						t.Fatal("shared verify route duplicated", err)
					}
					_, _, err = identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Confirmation", Version: "1"}}, ops, nil)
					if err != nil {
						t.Fatal("selected confirmation wire/router invalid", err)
					}
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), `"activated":true`) {
				t.Fatal("invalid result delivered activation", mode, w.Code)
			}
			if (mode == "missing-variant" || mode == "duplicate-variant" || mode == "login-fields") && (owner.calls != 0 || owner.reads != 0) {
				t.Fatal("alternate variant acquired custody")
			}
		})
	}
}
