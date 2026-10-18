package turnstile

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk/captcha"
)

func profileEvidence(p captcha.Config) captcha.ProviderEvidence {
	return captcha.ProviderEvidence{Provider: p.Provider, API: p.API, Version: p.Version, Tier: p.Tier, APIProfile: p.APIProfile, SiteKey: p.SiteKey, ConfigurationVersion: p.ConfigurationVersion, Kind: captcha.EvidenceTurnstile, Turnstile: &captcha.TurnstileEvidence{}}
}

// Siteverify returns the closed fields documented by Cloudflare's server-side
// validation contract. Duplicate keys (including escaped aliases), unknown
// extensions and trailing JSON are not an attributable supported response.
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
	seen := make(map[string]bool, 7)
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || len(key) > 32 || seen[key] || len(seen) >= 7 {
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
		case "action":
			value, err := stringField(d, 32, true)
			if err != nil || !widgetData(value, 32) {
				return base, captcha.ErrMalformedResponse
			}
			e.Action = captcha.OptionalString{Available: true, Value: value}
		case "cdata":
			value, err := stringField(d, 255, true)
			if err != nil || !widgetData(value, 255) {
				return base, captcha.ErrMalformedResponse
			}
			e.Turnstile.CData = captcha.OptionalString{Available: true, Value: value}
		case "error-codes":
			codes, err := errorCodes(d)
			if err != nil {
				return base, err
			}
			e.Turnstile.ErrorCodesAvailable = true
			e.Turnstile.ErrorCodes = codes
			e.ReasonCodes = append([]string(nil), codes...)
		case "metadata":
			value, err := metadata(d)
			if err != nil {
				return base, err
			}
			e.Turnstile.MetadataAvailable = true
			e.Turnstile.EphemeralID = value
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
	if e.Success && len(e.ReasonCodes) != 0 || !e.Success && len(e.ReasonCodes) == 0 {
		return base, captcha.ErrMalformedResponse
	}
	return e, nil
}

func stringField(d *json.Decoder, maximum int, empty bool) (string, error) {
	value, err := d.Token()
	text, ok := value.(string)
	if err != nil || !ok || len(text) > maximum || !empty && text == "" {
		return "", captcha.ErrMalformedResponse
	}
	for _, b := range []byte(text) {
		if b < 33 || b > 126 {
			return "", captcha.ErrMalformedResponse
		}
	}
	return text, nil
}

// Widget action/cData limits and alphabet are Cloudflare's documented widget
// configuration contract, not an application-specific truncation policy.
func widgetData(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
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
		if err != nil || !knownCode(code) {
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

func knownCode(code string) bool {
	switch code {
	case "missing-input-secret", "invalid-input-secret", "missing-input-response", "invalid-input-response", "bad-request", "timeout-or-duplicate", "internal-error":
		return true
	default:
		return false
	}
}

func metadata(d *json.Decoder) (captcha.OptionalString, error) {
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return captcha.OptionalString{}, captcha.ErrMalformedResponse
	}
	var value captcha.OptionalString
	for d.More() {
		key, err := d.Token()
		if err != nil || key != "ephemeral_id" || value.Available {
			return captcha.OptionalString{}, captcha.ErrMalformedResponse
		}
		text, err := stringField(d, 256, false)
		if err != nil {
			return captcha.OptionalString{}, err
		}
		value = captcha.OptionalString{Available: true, Value: text}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return captcha.OptionalString{}, captcha.ErrMalformedResponse
	}
	return value, nil
}
