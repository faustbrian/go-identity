package captchafox

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func profileEvidence(p captcha.Config) captcha.ProviderEvidence {
	return captcha.ProviderEvidence{Provider: p.Provider, API: p.API, Version: p.Version, Tier: p.Tier, APIProfile: p.APIProfile, SiteKey: p.SiteKey, ConfigurationVersion: p.ConfigurationVersion, Kind: captcha.EvidenceCaptchaFox, CaptchaFox: &captcha.CaptchaFoxEvidence{}}
}

// Free Siteverify documents success-only challenge_ts, optional hostname and
// failure-only error-codes. Enterprise insights and generic action/score/sitekey
// are not returned by this selected schema. Unknown fields fail closed rather
// than silently selecting a different tier or manufacturing binding evidence.
// https://docs.captchafox.com/en/getting-started#verification-response
func parseBody(body []byte, p captcha.Config) (captcha.ProviderEvidence, error) {
	base := profileEvidence(p)
	if len(body) == 0 || len(body) > 64<<10 {
		return base, captcha.ErrMalformedResponse
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return base, captcha.ErrMalformedResponse
	}
	e := profileEvidence(p)
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(key) > 32 || seen[key] || len(seen) >= 4 {
			return base, captcha.ErrMalformedResponse
		}
		seen[key] = true
		switch key {
		case "success":
			value, err := d.Token()
			success, ok := value.(bool)
			if err != nil || !ok {
				return base, captcha.ErrMalformedResponse
			}
			e.Success = success
		case "challenge_ts":
			value, err := stringField(d, 64, false)
			if err != nil {
				return base, err
			}
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return base, captcha.ErrMalformedResponse
			}
			e.ChallengeTime = captcha.OptionalTime{Available: true, Value: at.UTC()}
		case "hostname":
			value, err := stringField(d, 253, true)
			if err != nil {
				return base, err
			}
			e.Hostname = captcha.OptionalString{Available: true, Value: value}
		case "error-codes":
			codes, err := errorCodes(d)
			if err != nil {
				return base, err
			}
			e.CaptchaFox.ErrorCodesAvailable = true
			e.CaptchaFox.ErrorCodes = codes
			for _, code := range codes {
				if knownCode(code) {
					e.ReasonCodes = append(e.ReasonCodes, code)
				} else {
					e.ReasonCodes = append(e.ReasonCodes, "unknown-provider-code")
				}
			}
		default:
			return base, captcha.ErrMalformedResponse
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || !seen["success"] {
		return base, captcha.ErrMalformedResponse
	}
	if _, err = d.Token(); err != io.EOF {
		return base, captcha.ErrMalformedResponse
	}
	if e.Success && e.CaptchaFox.ErrorCodesAvailable || !e.Success && e.ChallengeTime.Available {
		return e, captcha.ErrMalformedResponse
	}
	return e, nil
}

func stringField(d *json.Decoder, maximum int, empty bool) (string, error) {
	value, err := d.Token()
	s, ok := value.(string)
	if err != nil || !ok || !safeASCII(s, maximum, empty) {
		return "", captcha.ErrMalformedResponse
	}
	return s, nil
}

func errorCodes(d *json.Decoder) ([]string, error) {
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return nil, captcha.ErrMalformedResponse
	}
	codes := make([]string, 0, 4)
	for d.More() {
		if len(codes) >= 16 {
			return nil, captcha.ErrMalformedResponse
		}
		code, err := stringField(d, 64, false)
		if err != nil || !codeToken(code) {
			return nil, captcha.ErrMalformedResponse
		}
		codes = append(codes, code)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') {
		return nil, captcha.ErrMalformedResponse
	}
	return codes, nil
}

// Safe unknown code tokens remain attributable but cannot produce usable facts.
func codeToken(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}

func knownCode(s string) bool {
	switch s {
	case "missing-input-secret", "invalid-input-secret", "missing-input-response", "invalid-input-response", "bad-request", "timeout-or-duplicate", "invalid-ip-match":
		return true
	default:
		return false
	}
}
