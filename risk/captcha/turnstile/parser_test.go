package turnstile

import (
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func FuzzSiteverify(f *testing.F) {
	for _, seed := range []string{
		`{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com","action":"signup","cdata":"synthetic-cdata","error-codes":[]}`,
		`{"success":false,"error-codes":["timeout-or-duplicate"]}`,
		`{"success":true,"succ\u0065ss":false}`,
		`{"success":true,"metadata":{"ephemeral_id":"synthetic-enterprise-only","ephemeral_id":"other"}}`,
		`{"success":false,"error-codes":["unknown-error"]}`,
		strings.Repeat(" ", 65537),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		p := captcha.Config{Provider: "turnstile", API: "siteverify", Version: "v0", Tier: "free", APIProfile: "siteverify/v0", SiteKey: "synthetic-site", ConfigurationVersion: "synthetic-v1"}
		got, err := parseBody([]byte(body), p)
		if got.Turnstile == nil || got.Kind != captcha.EvidenceTurnstile || got.Provider != p.Provider {
			t.Fatal("parser lost selected profile even on failure")
		}
		if err == nil {
			if len(body) > 65536 || len(got.ReasonCodes) > 16 || len(got.Turnstile.CData.Value) > 255 || len(got.Turnstile.EphemeralID.Value) > 256 || got.Success && len(got.ReasonCodes) > 0 || !got.Success && len(got.ReasonCodes) == 0 {
				t.Fatal("accepted response escaped closed bounds")
			}
			for _, code := range got.ReasonCodes {
				if !knownCode(code) {
					t.Fatal("unknown provider diagnostic survived")
				}
			}
		}
	})
}
