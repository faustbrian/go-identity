// Package delivery owns provider-neutral, privacy-sensitive identity messages.
// Validation is not recipient ownership, authentication, queue admission or
// evidence of delivery. Durable orchestration is a separate composition boundary.
package delivery

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"
	"unicode/utf8"
)

// ErrInvalidInput rejects malformed, conflicting or unbounded message values.
// It never retains or describes the caller's recipient, code, URL or content.
var ErrInvalidInput = errors.New("delivery: invalid input")

// Channel selects the final transport context. Zero and unknown values are invalid.
type Channel uint8

const (
	// ChannelEmail selects an email message, not a claim of email ownership.
	ChannelEmail Channel = iota + 1
	// ChannelSMS selects an SMS message, not a claim of phone ownership.
	ChannelSMS
)

// Recipient is a sensitive transport address bound to a workflow-owned digest.
// ScopeDigest must be 64 lowercase hex bytes and must be derived by the owning
// workflow's scoped policy; this package cannot prove the caller's digest.
// Callers must not mutate fields while validation or rendering is in progress.
type Recipient struct {
	Channel     Channel
	Address     string
	ScopeDigest string
}

// TemplateVariable is a closed tagged value. Kind is text, url, code or timestamp;
// non-selected fields must be zero. Empty text is valid; codes/URLs/times are not.
// Sensitive is schema metadata, never permission to log a false-marked value.
// Validate checks shape; the renderer additionally enforces schema and URL origin.
type TemplateVariable struct {
	Name      string
	Kind      string
	TextValue string
	URLValue  string
	CodeValue string
	TimeValue time.Time
	Sensitive bool
}

// Message is the caller-owned versioned intent. LocaleChain is a pre-negotiated
// ordered list, not request/session locale input. Neither successful validation
// nor rendering queues a message or proves recipient existence or delivery.
// Callers must not mutate slices/fields during a call; retained values must be
// copied by the renderer/queue at their own ownership boundary.
type Message struct {
	Purpose         string
	Channel         Channel
	Recipient       Recipient
	TemplateID      string
	TemplateVersion uint64
	LocaleChain     []string
	Variables       []TemplateVariable
}

func validChannel(c Channel) bool { return c == ChannelEmail || c == ChannelSMS }

func boundedText(s string, min, max int) bool {
	return len(s) >= min && len(s) <= max && utf8.ValidString(s)
}

func printableASCII(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func variableName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' || i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	return true
}

func purposeName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b >= 'a' && b <= 'z' || i > 0 && (b >= '0' && b <= '9' || b == '-' || b == '.') {
			continue
		}
		return false
	}
	return true
}

func localeShape(s string) bool {
	if len(s) == 0 || len(s) > 35 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if b == '-' && i > 0 && s[i-1] != '-' {
			continue
		}
		return false
	}
	return true
}

// Validate enforces UTF-8/byte bounds, channel and digest shape, and rejects
// address controls/header injection. It deliberately does not normalize or
// establish email/phone ownership; the owning workflow supplies its validated
// canonical address and exact scope. Zero Recipient is invalid.
func (r Recipient) Validate() error {
	if !validChannel(r.Channel) || !boundedText(r.Address, 1, 320) || len(r.ScopeDigest) != 64 {
		return ErrInvalidInput
	}
	for _, c := range r.Address {
		if c < 0x20 || c == 0x7f {
			return ErrInvalidInput
		}
	}
	for i := range len(r.ScopeDigest) {
		b := r.ScopeDigest[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return ErrInvalidInput
		}
	}
	return nil
}

// Validate checks the complete union before use. Text is at most4096 UTF-8 bytes;
// code is 1..128 printable ASCII bytes. URL is 1..2048 bytes, absolute HTTPS,
// with a host, no userinfo/opaque form and no controls. Origin authorization is
// the selected template's responsibility, not granted by this shape check.
// Timestamp must be a nonzero UTC instant in years1..9999.
func (v TemplateVariable) Validate() error {
	if !variableName(v.Name) {
		return ErrInvalidInput
	}
	switch v.Kind {
	case "text":
		if !boundedText(v.TextValue, 0, 4096) || v.URLValue != "" || v.CodeValue != "" || !v.TimeValue.IsZero() {
			return ErrInvalidInput
		}
	case "url":
		if v.TextValue != "" || v.CodeValue != "" || !v.TimeValue.IsZero() || !boundedText(v.URLValue, 1, 2048) {
			return ErrInvalidInput
		}
		for _, c := range v.URLValue {
			if c <= 0x20 || c == 0x7f {
				return ErrInvalidInput
			}
		}
		u, err := url.Parse(v.URLValue)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
			return ErrInvalidInput
		}
	case "code":
		if v.TextValue != "" || v.URLValue != "" || !v.TimeValue.IsZero() || !printableASCII(v.CodeValue, 1, 128) {
			return ErrInvalidInput
		}
	case "timestamp":
		_, offset := v.TimeValue.Zone()
		if v.TextValue != "" || v.URLValue != "" || v.CodeValue != "" || v.TimeValue.IsZero() || offset != 0 || v.TimeValue.Year() < 1 || v.TimeValue.Year() > 9999 {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

// Validate checks bounded intent structure, channel binding and duplicate-free
// variable names and locale entries before template selection. Locale shape
// validation is not BCP47 negotiation/canonicalization; callers provide canonical
// tags from their locale policy. Schema matching and origin policy occur later.
func (m Message) Validate() error {
	if !purposeName(m.Purpose) || !validChannel(m.Channel) || m.Recipient.Channel != m.Channel || m.Recipient.Validate() != nil || !printableASCII(m.TemplateID, 1, 128) || m.TemplateVersion == 0 || len(m.LocaleChain) < 1 || len(m.LocaleChain) > 8 || len(m.Variables) > 64 {
		return ErrInvalidInput
	}
	seenLocales := make(map[string]struct{}, len(m.LocaleChain))
	for _, locale := range m.LocaleChain {
		if !localeShape(locale) {
			return ErrInvalidInput
		}
		if _, duplicate := seenLocales[locale]; duplicate {
			return ErrInvalidInput
		}
		seenLocales[locale] = struct{}{}
	}
	seenVariables := make(map[string]struct{}, len(m.Variables))
	for _, variable := range m.Variables {
		if variable.Validate() != nil {
			return ErrInvalidInput
		}
		if _, duplicate := seenVariables[variable.Name]; duplicate {
			return ErrInvalidInput
		}
		seenVariables[variable.Name] = struct{}{}
	}
	return nil
}

func redact(s fmt.State) { _, _ = io.WriteString(s, "delivery(redacted)") }

// Format redacts every formatting verb, including invalid and zero recipients.
func (Recipient) Format(s fmt.State, _ rune) { redact(s) }

// Format redacts all union arms regardless of Sensitive or Kind.
func (TemplateVariable) Format(s fmt.State, _ rune) { redact(s) }

// Format redacts the complete message, including embedded recipient/variables.
func (Message) Format(s fmt.State, _ rune) { redact(s) }

// LogValue redacts recipient diagnostics; explicit Address remains sensitive.
func (Recipient) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// LogValue redacts variable diagnostics even when Sensitive is false.
func (TemplateVariable) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// LogValue redacts message diagnostics; field projections remain sensitive.
func (Message) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// MarshalJSON refuses implicit sensitive serialization with errors.ErrUnsupported.
func (Recipient) MarshalJSON() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalText refuses implicit sensitive serialization with errors.ErrUnsupported.
func (Recipient) MarshalText() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalJSON refuses implicit sensitive serialization with errors.ErrUnsupported.
func (TemplateVariable) MarshalJSON() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalText refuses implicit sensitive serialization with errors.ErrUnsupported.
func (TemplateVariable) MarshalText() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalJSON refuses implicit sensitive serialization with errors.ErrUnsupported.
func (Message) MarshalJSON() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalText refuses implicit sensitive serialization with errors.ErrUnsupported.
func (Message) MarshalText() ([]byte, error) { return nil, errors.ErrUnsupported }
