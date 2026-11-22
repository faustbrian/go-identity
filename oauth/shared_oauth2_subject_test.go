package oauth

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestOAuth2UserInfoSubjectPreservesSelectedWireType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		encoding OAuth2SubjectEncoding
		value    any
		want     string
	}{
		{"exact UTF8", OAuth2StringSubject, "Tõnu/002", "Tõnu/002"},
		{"exact decimal-looking string", OAuth2StringSubject, "0042", "0042"},
		{"512 byte subject", OAuth2StringSubject, strings.Repeat("é", 256), strings.Repeat("é", 256)},
		{"over byte bound", OAuth2StringSubject, strings.Repeat("é", 257), ""},
		{"empty", OAuth2StringSubject, "", ""},
		{"control", OAuth2StringSubject, "person\u0085x", ""},
		{"replacement rune", OAuth2StringSubject, "person\uFFFDx", ""},
		{"invalid UTF8", OAuth2StringSubject, "person\xff", ""},
		{"null", OAuth2StringSubject, nil, ""},
		{"number not string", OAuth2StringSubject, json.Number("42"), ""},
		{"legacy integer", OAuth2PositiveIntegerSubject, json.Number("42"), "42"},
		{"legacy string denied", OAuth2PositiveIntegerSubject, "42", ""},
		{"exponent not integer", OAuth2PositiveIntegerSubject, json.Number("4e1"), ""},
		{"unselected encoding", "", "person", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := oauth2UserInfoSubject(tc.value, tc.encoding)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatal("subject was coerced or accepted outside its selected wire type")
			}
		})
	}
}

func FuzzOAuth2UserInfoStringSubject(f *testing.F) {
	f.Add("Tõnu/002")
	f.Add("\uFFFD")
	f.Add("\x00")
	f.Add("\xff")
	f.Fuzz(func(t *testing.T, raw string) {
		subject, ok := oauth2UserInfoSubject(raw, OAuth2StringSubject)
		if !ok {
			if subject != "" {
				t.Fatal("rejection retained subject material")
			}
			return
		}
		if subject != raw || len(subject) < 1 || len(subject) > 512 || !utf8.ValidString(subject) || strings.ContainsRune(subject, utf8.RuneError) {
			t.Fatal("subject evidence lost exact valid string identity")
		}
	})
}
