package recaptcha

import (
	"testing"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func FuzzSiteverifyV3(f *testing.F) {
	for _, seed := range []string{`{"success":true,"score":0.1,"action":"signup","hostname":"example.com","challenge_ts":"2026-10-18T12:00:00Z"}`, `{"success":false,"error-codes":["timeout-or-duplicate"]}`, `{"success":false,"error-codes":["future-safe-code"]}`, `{"success":true,"score":1e999}`, `{"success":true,"success":false}`, `{"success":true,"error-codes":["bad-request"]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		e, err := parseBody(body, captcha.Config{Provider: "recaptcha", API: "classic_siteverify", Version: "v3", Tier: "standard", APIProfile: "classic_siteverify/v3"})
		if e.Recaptcha == nil || e.Turnstile != nil || e.Kind != captcha.EvidenceRecaptcha || len(e.Recaptcha.ErrorCodes) > 16 {
			t.Fatal("parser escaped attributable bounded union")
		}
		if err == nil && (e.Score < 0 || e.Score > 1 || e.Success && len(e.Recaptcha.ErrorCodes) > 0) {
			t.Fatal("parser accepted contradictory score/result")
		}
	})
}
