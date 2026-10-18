package captcha

import (
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"

	clock "github.com/faustbrian/go-clock"
)

// Config selects an explicit immutable provider profile and bounded call policy.
// Zero is invalid. Supported profiles are Turnstile Siteverify v0/free,
// reCAPTCHA classic Siteverify v3/standard, hCaptcha Siteverify Publisher/Pro and
// CaptchaFox Siteverify/free. All bind hostname/challenge time; hCaptcha and
// CaptchaFox have no action; only reCAPTCHA has score. None discloses remote IP
// or has origin evidence. No endpoint or
// provider is inferred from omitted configuration.
// Lifetime is 1s..2m, ChallengeMaxAge 1s..5m and Timeout 1s..15s. MaxTokenBytes
// is 1..8192; the provider additionally enforces its documented character limit.
// MaxConcurrent (1..256) bounds complete calls without a growing admission queue.
// Borrowed Clock must be bounded and concurrency-safe. Hostnames are canonical
// lowercase ASCII DNS names, never wildcards or suffix matches.
type Config struct {
	Provider, API, Version, Tier, APIProfile, SiteKey, ConfigurationVersion string
	Hostnames, Origins                                                      []string
	ExpectedAction                                                          string
	ExpectedCData                                                           OptionalString
	RemoteIPDisclosure                                                      bool
	MaxTokenBytes, MaxConcurrent                                            int
	Timeout, Lifetime, ChallengeMaxAge                                      time.Duration
	Clock                                                                   clock.Clock
}

func (c Config) valid() bool {
	if !ascii(c.SiteKey, 512, false) || !ascii(c.ConfigurationVersion, 64, false) || len(c.Hostnames) < 1 || len(c.Hostnames) > 32 || len(c.Origins) != 0 || c.RemoteIPDisclosure || c.MaxTokenBytes < 1 || c.MaxTokenBytes > 8192 || c.MaxConcurrent < 1 || c.MaxConcurrent > 256 || c.Timeout < time.Second || c.Timeout > 15*time.Second || c.Lifetime < time.Second || c.Lifetime > 2*time.Minute || c.ChallengeMaxAge < time.Second || c.ChallengeMaxAge > 5*time.Minute || nilDependency(c.Clock) || !optionalString(c.ExpectedCData, 255) {
		return false
	}
	switch c.Provider {
	case "turnstile":
		if c.API != "siteverify" || c.Version != "v0" || c.Tier != "free" || c.APIProfile != "siteverify/v0" || !action(c.ExpectedAction) {
			return false
		}
	case "recaptcha":
		// Google's v3 Actions contract allows alphanumerics, slash and underscore;
		// its Token Restrictions cap challenge validity at two minutes.
		// https://developers.google.com/recaptcha/docs/v3
		if c.API != "classic_siteverify" || c.Version != "v3" || c.Tier != "standard" || c.APIProfile != "classic_siteverify/v3" || !recaptchaAction(c.ExpectedAction) || c.ChallengeMaxAge > 2*time.Minute || c.ExpectedCData.Available {
			return false
		}
	case "hcaptcha":
		// Publisher/Pro Siteverify documents hostname/challenge and optional credit,
		// not action, origin or score. The reference pins this contract revision;
		// 120s is the provider's documented default expiry, never extended here.
		// https://docs.hcaptcha.com/#verify-the-user-response-server-side
		if c.API != "siteverify" || c.Version != "2026-08-11" || c.Tier != "publisher_pro" || c.APIProfile != "siteverify/publisher_pro" || c.ExpectedAction != "" || c.ExpectedCData.Available || c.ChallengeMaxAge > 2*time.Minute {
			return false
		}
	case "captchafox":
		// The Free response has no action, score, origin or Enterprise insights.
		// No numeric provider TTL is documented: ChallengeMaxAge is an explicit
		// bounded local policy, not a claim about provider token validity.
		// https://docs.captchafox.com/en/getting-started#verification-response
		if c.API != "siteverify" || c.Version != "2026-08-11" || c.Tier != "free" || c.APIProfile != "siteverify/free" || c.ExpectedAction != "" || c.ExpectedCData.Available {
			return false
		}
	default:
		return false
	}
	for i, host := range c.Hostnames {
		if !hostname(host) || slices.Contains(c.Hostnames[:i], host) {
			return false
		}
		// hCaptcha uses this literal when hostname reporting is suppressed;
		// accepting it as a configured host would invent a positive binding.
		// https://docs.hcaptcha.com/#verify-the-user-response-server-side
		if c.Provider == "hcaptcha" && host == "not-provided" {
			return false
		}
	}
	return true
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Capabilities returns only the supported selected profile, or zero for invalid
// configuration. It does not claim provider availability or authorize issuance.
func (c Config) Capabilities() ProviderCapabilities {
	if !c.valid() {
		return ProviderCapabilities{}
	}
	return ProviderCapabilities{Hostname: true, Action: c.Provider == "turnstile" || c.Provider == "recaptcha", ChallengeTime: true, ProviderIdempotency: c.Provider == "turnstile", Score: c.Provider == "recaptcha"}
}

func recaptchaAction(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '/') {
			return false
		}
	}
	return true
}

func ascii(value string, maximum int, empty bool) bool {
	if len(value) > maximum || !empty && value == "" {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func optionalString(value OptionalString, maximum int) bool {
	return !value.Available && value.Value == "" || value.Available && ascii(value.Value, maximum, true)
}

func action(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func hostname(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}

func (Config) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "captcha.Config(redacted)") }
func (Config) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (Config) MarshalText() ([]byte, error) { return nil, errSensitive }
