package captchafox

import (
	"testing"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func FuzzFreeSiteverify(f *testing.F) {
	for _, seed := range []string{`{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com"}`, `{"success":false,"error-codes":["timeout-or-duplicate"]}`, `{"success":true,"error-codes":[]}`, `{"success":false,"challenge_ts":"2026-10-18T11:59:30Z"}`, `{"success":true,"success":false}`, `{"success":false,"error-codes":["future-safe-code"]}`, `{"success":true,"insights":{}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		e, err := parseBody(body, captcha.Config{Provider: "captchafox", API: "siteverify", Version: "2026-08-11", Tier: "free", APIProfile: "siteverify/free"})
		if e.CaptchaFox == nil || e.Kind != captcha.EvidenceCaptchaFox || e.Recaptcha != nil || e.Turnstile != nil || e.HCaptcha != nil || len(e.CaptchaFox.ErrorCodes) > 16 {
			t.Fatal("parser escaped attributable bounded union")
		}
		if err == nil && (e.ScoreAvailable || e.Action.Available || e.Origin.Available || e.Success && e.CaptchaFox.ErrorCodesAvailable || !e.Success && e.ChallengeTime.Available) {
			t.Fatal("parser accepted unsupported or contradictory provider facts")
		}
	})
}
