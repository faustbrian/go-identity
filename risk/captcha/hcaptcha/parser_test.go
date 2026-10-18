package hcaptcha

import (
	"testing"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func FuzzPublisherSiteverify(f *testing.F) {
	for _, seed := range []string{`{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com","credit":false}`, `{"success":true,"credit":null}`, `{"success":false,"error-codes":["already-seen-response"]}`, `{"success":true,"success":false}`, `{"success":false,"error-codes":["future-safe-code"]}`, `{"success":true,"score":0.9}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		e, err := parseBody(body, captcha.Config{Provider: "hcaptcha", API: "siteverify", Version: "2026-08-11", Tier: "publisher_pro", APIProfile: "siteverify/publisher_pro"})
		if e.HCaptcha == nil || e.Kind != captcha.EvidenceHCaptcha || e.Recaptcha != nil || e.Turnstile != nil || e.CaptchaFox != nil || len(e.HCaptcha.ErrorCodes) > 16 {
			t.Fatal("parser escaped attributable bounded union")
		}
		if err == nil && (e.ScoreAvailable || e.Action.Available || e.HCaptcha.ReturnedSiteKey.Available || e.HCaptcha.ScoreReasonsAvailable || e.Success && len(e.HCaptcha.ErrorCodes) > 0) {
			t.Fatal("parser fabricated unsupported field or contradictory success")
		}
	})
}
