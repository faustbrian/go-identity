package hcaptcha

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func profileEvidence(p captcha.Config) captcha.ProviderEvidence {
	return captcha.ProviderEvidence{Provider: p.Provider, API: p.API, Version: p.Version, Tier: p.Tier, APIProfile: p.APIProfile, SiteKey: p.SiteKey, ConfigurationVersion: p.ConfigurationVersion, Kind: captcha.EvidenceHCaptcha, HCaptcha: &captcha.HCaptchaEvidence{}}
}

// Publisher/Pro fields are pinned by hCaptcha's documented Siteverify response.
// Duplicate/escaped-alias keys, undocumented fields and trailing JSON fail closed.
// Hostname is browser-derived consistency evidence, not authentication. No
// returned sitekey/action/score is documented for this tier: do not fabricate it.
// https://docs.hcaptcha.com/#verify-the-user-response-server-side
func parseBody(body []byte, p captcha.Config) (captcha.ProviderEvidence, error) {
	base := profileEvidence(p)
	if len(body) == 0 || len(body) > 64<<10 {
		return base, captcha.ErrMalformedResponse
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return base, captcha.ErrMalformedResponse
	}
	e := profileEvidence(p)
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(key) > 32 || seen[key] || len(seen) >= 5 {
			return base, captcha.ErrMalformedResponse
		}
		seen[key] = true
		switch key {
		case "success":
			v, err := d.Token()
			value, ok := v.(bool)
			if err != nil || !ok {
				return base, captcha.ErrMalformedResponse
			}
			e.Success = value
		case "credit":
			value, err := d.Token()
			credit, ok := value.(bool)
			if err != nil || !ok {
				return base, captcha.ErrMalformedResponse
			}
			e.HCaptcha.CreditAvailable, e.HCaptcha.Credit = true, credit
		case "challenge_ts":
			v, err := stringField(d, 64, false)
			if err != nil {
				return base, err
			}
			at, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return base, captcha.ErrMalformedResponse
			}
			e.ChallengeTime = captcha.OptionalTime{Available: true, Value: at.UTC()}
		case "hostname":
			v, err := stringField(d, 253, true)
			if err != nil {
				return base, err
			}
			e.Hostname = captcha.OptionalString{Available: true, Value: v}
		case "error-codes":
			codes, err := errorCodes(d)
			if err != nil {
				return base, err
			}
			e.HCaptcha.ErrorCodesAvailable = true
			e.HCaptcha.ErrorCodes = codes
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
	if e.Success && len(e.HCaptcha.ErrorCodes) != 0 {
		return e, captcha.ErrMalformedResponse
	}
	return e, nil
}

func stringField(d *json.Decoder, maximum int, empty bool) (string, error) {
	v, err := d.Token()
	s, ok := v.(string)
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

// Unrecognized safe code tokens survive only in the redacted native envelope;
// they produce unusable malformed evidence, never a guessed positive result.
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
	case "missing-input-secret", "invalid-input-secret", "missing-input-response", "invalid-input-response", "expired-input-response", "already-seen-response", "bad-request", "missing-remoteip", "invalid-remoteip", "not-using-dummy-passcode", "sitekey-secret-mismatch":
		return true
	default:
		return false
	}
}
