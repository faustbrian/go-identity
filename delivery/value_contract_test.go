package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTaggedVariablesRejectConflictingArms(t *testing.T) {
	valid := []TemplateVariable{
		{Name: "name", Kind: "text", TextValue: "<display>"},
		{Name: "empty", Kind: "text"},
		{Name: "link", Kind: "url", URLValue: "https://example.invalid/verify?q=synthetic", Sensitive: true},
		{Name: "code", Kind: "code", CodeValue: "synthetic-only", Sensitive: true},
		{Name: "date", Kind: "timestamp", TimeValue: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, variable := range valid {
		if err := variable.Validate(); err != nil {
			t.Fatal("valid tagged value rejected")
		}
	}
	for _, variable := range []TemplateVariable{
		{}, {Name: "x", Kind: "unknown"}, {Name: "x", Kind: "text", CodeValue: "synthetic"},
		{Name: "x", Kind: "url", TextValue: "conflict", URLValue: "https://example.invalid"},
		{Name: "x", Kind: "code"}, {Name: "x", Kind: "code", CodeValue: "line\nbreak"},
		{Name: "x", Kind: "timestamp"}, {Name: "x", Kind: "text", TextValue: string([]byte{0xff})},
		{Name: "x", Kind: "text", TextValue: strings.Repeat("x", 4097)},
		{Name: "x", Kind: "url", URLValue: "http://example.invalid"},
		{Name: "x", Kind: "url", URLValue: "https://user@example.invalid"},
		{Name: "x", Kind: "url", URLValue: "//example.invalid"},
		{Name: "x", Kind: "url", URLValue: "https://example.invalid/\n"},
		{Name: "bad name", Kind: "text"},
	} {
		if err := variable.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid union became usable")
		}
	}
}

func validMessage() Message {
	return Message{Purpose: "email-verification", Channel: ChannelEmail,
		Recipient:  Recipient{Channel: ChannelEmail, Address: "person@example.invalid", ScopeDigest: strings.Repeat("a", 64)},
		TemplateID: "verify", TemplateVersion: 1, LocaleChain: []string{"en-US", "en"},
		Variables: []TemplateVariable{{Name: "name", Kind: "text", TextValue: "synthetic-display"}},
	}
}

func TestMessageBoundsAndChannelBinding(t *testing.T) {
	if err := validMessage().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Message){
		func(m *Message) { m.Purpose = "" }, func(m *Message) { m.Purpose = "Upper" },
		func(m *Message) { m.Channel = 0 }, func(m *Message) { m.Recipient.Channel = ChannelSMS },
		func(m *Message) { m.Recipient.Address = "" }, func(m *Message) { m.Recipient.Address = "a\r\nb" },
		func(m *Message) { m.Recipient.ScopeDigest = strings.Repeat("A", 64) },
		func(m *Message) { m.Recipient.ScopeDigest = strings.Repeat("a", 63) },
		func(m *Message) { m.TemplateVersion = 0 }, func(m *Message) { m.TemplateID = "" },
		func(m *Message) { m.LocaleChain = nil },
		func(m *Message) { m.LocaleChain = []string{"en", "en"} },
		func(m *Message) { m.LocaleChain = []string{"en\r\n"} },
		func(m *Message) { m.Variables = append(m.Variables, m.Variables[0]) },
		func(m *Message) { m.Variables = make([]TemplateVariable, 65) },
	} {
		m := validMessage()
		mutate(&m)
		if err := m.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid intent passed admission validation")
		}
	}
	m := validMessage()
	m.Variables = nil
	if err := m.Validate(); err != nil {
		t.Fatal("absent optional variables rejected")
	}
}

func TestSensitiveValueDiagnostics(t *testing.T) {
	m := validMessage()
	marker := "synthetic-sensitive-marker"
	m.Recipient.Address = marker
	m.Variables[0].TextValue = marker
	for _, value := range []any{m, &m, m.Recipient, &m.Recipient, m.Variables[0], &m.Variables[0]} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if text := fmt.Sprintf(verb, value); strings.Contains(text, marker) || !strings.Contains(text, "redacted") {
				t.Fatal("sensitive diagnostic escaped")
			}
		}
		var output strings.Builder
		slog.New(slog.NewJSONHandler(&output, nil)).Info("synthetic", "value", value)
		if strings.Contains(output.String(), marker) {
			t.Fatal("structured logging escaped")
		}
		if data, err := json.Marshal(value); err == nil || len(data) != 0 {
			t.Fatal("implicit serialization escaped")
		}
	}
}

func TestValueByteAndCountEndpoints(t *testing.T) {
	v := TemplateVariable{Name: strings.Repeat("n", 64), Kind: "text", TextValue: strings.Repeat("é", 2048)}
	if err := v.Validate(); err != nil {
		t.Fatal("exact byte bound rejected")
	}
	v.TextValue += "x"
	if !errors.Is(v.Validate(), ErrInvalidInput) {
		t.Fatal("final extra byte admitted")
	}
	v = TemplateVariable{Name: "code", Kind: "code", CodeValue: strings.Repeat("x", 128)}
	if err := v.Validate(); err != nil {
		t.Fatal("exact code bound rejected")
	}
	v.CodeValue += "x"
	if !errors.Is(v.Validate(), ErrInvalidInput) {
		t.Fatal("oversized code admitted")
	}
	m := validMessage()
	m.Recipient.Address = strings.Repeat("é", 160)
	m.Purpose = strings.Repeat("a", 64)
	m.TemplateID = strings.Repeat("t", 128)
	m.LocaleChain = []string{"aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"}
	m.Variables = make([]TemplateVariable, 64)
	for i := range m.Variables {
		m.Variables[i] = TemplateVariable{Name: fmt.Sprintf("v%d", i), Kind: "text"}
	}
	if err := m.Validate(); err != nil {
		t.Fatal("valid collection/byte endpoints rejected")
	}
	for _, mutate := range []func(*Message){
		func(m *Message) { m.Recipient.Address += "x" },
		func(m *Message) { m.Purpose += "a" },
		func(m *Message) { m.TemplateID += "t" },
		func(m *Message) { m.LocaleChain = append(m.LocaleChain, "ai") },
		func(m *Message) { m.Variables = append(m.Variables, TemplateVariable{Name: "extra", Kind: "text"}) },
	} {
		copy := m
		mutate(&copy)
		if !errors.Is(copy.Validate(), ErrInvalidInput) {
			t.Fatal("out-of-bound intent admitted")
		}
	}
}

func TestURLTimestampLocaleAndTextSerializationBoundaries(t *testing.T) {
	prefix := "https://example.invalid/"
	v := TemplateVariable{Name: "link", Kind: "url", URLValue: prefix + strings.Repeat("a", 2048-len(prefix))}
	if err := v.Validate(); err != nil {
		t.Fatal("exact URL bound rejected")
	}
	v.URLValue += "a"
	if !errors.Is(v.Validate(), ErrInvalidInput) {
		t.Fatal("URL extra byte admitted")
	}
	for _, instant := range []time.Time{time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)} {
		v = TemplateVariable{Name: "time", Kind: "timestamp", TimeValue: instant}
		if err := v.Validate(); err != nil {
			t.Fatal("valid UTC endpoint rejected")
		}
	}
	for _, instant := range []time.Time{time.Time{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))} {
		v = TemplateVariable{Name: "time", Kind: "timestamp", TimeValue: instant}
		if !errors.Is(v.Validate(), ErrInvalidInput) {
			t.Fatal("invalid timestamp admitted")
		}
	}
	m := validMessage()
	m.LocaleChain = []string{strings.Repeat("a", 35)}
	if err := m.Validate(); err != nil {
		t.Fatal("locale byte bound rejected")
	}
	m.LocaleChain[0] += "a"
	if !errors.Is(m.Validate(), ErrInvalidInput) {
		t.Fatal("locale extra byte admitted")
	}
	for _, value := range []interface{ MarshalText() ([]byte, error) }{m, &m, m.Recipient, &m.Recipient, v, &v} {
		data, err := value.MarshalText()
		if !errors.Is(err, errors.ErrUnsupported) || len(data) != 0 {
			t.Fatal("text serialization escaped")
		}
	}
}

func FuzzTaggedVariable(f *testing.F) {
	f.Add("name", "text", "synthetic", "", "", int64(0))
	f.Add("link", "url", "", "https://example.invalid/a", "", int64(0))
	f.Add("code", "code", "", "", "synthetic", int64(0))
	f.Add("time", "timestamp", "", "", "", int64(1767225600))
	f.Fuzz(func(t *testing.T, name, kind, text, link, code string, seconds int64) {
		v := TemplateVariable{Name: name, Kind: kind, TextValue: text, URLValue: link, CodeValue: code}
		if seconds != 0 {
			v.TimeValue = time.Unix(seconds, 0).UTC()
		}
		err := v.Validate()
		if err != nil {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatal("unstable classification")
			}
			return
		}
		if len(v.Name) < 1 || len(v.Name) > 64 {
			t.Fatal("accepted name bound violated")
		}
		switch v.Kind {
		case "text":
			if len(v.TextValue) > 4096 || !utf8.ValidString(v.TextValue) || v.URLValue != "" || v.CodeValue != "" || !v.TimeValue.IsZero() {
				t.Fatal("accepted text union conflicts")
			}
		case "url":
			if len(v.URLValue) < 1 || len(v.URLValue) > 2048 || v.TextValue != "" || v.CodeValue != "" || !v.TimeValue.IsZero() {
				t.Fatal("accepted URL union conflicts")
			}
			u, err := url.Parse(v.URLValue)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
				t.Fatal("accepted unsafe URL")
			}
			for _, c := range v.URLValue {
				if c <= 0x20 || c == 0x7f {
					t.Fatal("accepted URL controls")
				}
			}
		case "code":
			if len(v.CodeValue) < 1 || len(v.CodeValue) > 128 || v.TextValue != "" || v.URLValue != "" || !v.TimeValue.IsZero() {
				t.Fatal("accepted code union conflicts")
			}
			for i := range len(v.CodeValue) {
				if v.CodeValue[i] < 0x21 || v.CodeValue[i] > 0x7e {
					t.Fatal("accepted nonprintable code")
				}
			}
		case "timestamp":
			_, offset := v.TimeValue.Zone()
			if v.TimeValue.IsZero() || v.TimeValue.Year() < 1 || v.TimeValue.Year() > 9999 || offset != 0 || v.TextValue != "" || v.URLValue != "" || v.CodeValue != "" {
				t.Fatal("accepted timestamp union conflicts")
			}
		default:
			t.Fatal("accepted unknown union kind")
		}
	})
}
