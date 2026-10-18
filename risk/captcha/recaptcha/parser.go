package recaptcha

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"time"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func profileEvidence(p captcha.Config) captcha.ProviderEvidence {
	return captcha.ProviderEvidence{Provider: p.Provider, API: p.API, Version: p.Version, Tier: p.Tier, APIProfile: p.APIProfile, SiteKey: p.SiteKey, ConfigurationVersion: p.ConfigurationVersion, Kind: captcha.EvidenceRecaptcha, Recaptcha: &captcha.RecaptchaEvidence{}}
}

// Only Google's web v3 Site Verify Response fields are supported. Duplicate
// keys (including escaped aliases), Android/Enterprise fields and trailing JSON
// cannot be attributed to this profile. The response byte budget precedes parsing.
// https://developers.google.com/recaptcha/docs/v3#site_verify_response
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
	seen := make(map[string]bool, 6)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(key) > 32 || seen[key] || len(seen) >= 6 {
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
		case "score":
			v, err := d.Token()
			number, ok := v.(json.Number)
			if err != nil || !ok {
				return base, captcha.ErrMalformedResponse
			}
			score, err := number.Float64()
			if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
				return base, captcha.ErrMalformedResponse
			}
			e.ScoreAvailable, e.Score = true, score
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
		case "action":
			v, err := stringField(d, 64, true)
			if err != nil || !action(v, true) {
				return base, captcha.ErrMalformedResponse
			}
			e.Action = captcha.OptionalString{Available: true, Value: v}
		case "error-codes":
			codes, err := errorCodes(d)
			if err != nil {
				return base, err
			}
			e.Recaptcha.ErrorCodesAvailable = true
			e.Recaptcha.ErrorCodes = codes
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
	if e.Success && len(e.Recaptcha.ErrorCodes) != 0 {
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

// v3 action names are non-user-specific alphanumeric/slash/underscore labels.
// The 64-byte selected-profile budget is the reference configuration bound.
// https://developers.google.com/recaptcha/docs/v3#actions
func action(s string, empty bool) bool {
	if len(s) > 64 || !empty && s == "" {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '/') {
			return false
		}
	}
	return true
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
	case "missing-input-secret", "invalid-input-secret", "missing-input-response", "invalid-input-response", "bad-request", "timeout-or-duplicate":
		return true
	default:
		return false
	}
}
