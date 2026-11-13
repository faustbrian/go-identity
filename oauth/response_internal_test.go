package oauth

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func parserConfig() OIDCConfig {
	return OIDCConfig{MaxResponseBytes: 64 << 10, MaxTokenBytes: 16 << 10, Scopes: []string{"openid", "profile"}}
}

func TestTokenResponseHostileBoundaries(t *testing.T) {
	valid := `{"access_token":"access","id_token":"id","token_type":"Bearer","expires_in":60}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", valid, true},
		{"subset", strings.TrimSuffix(valid, "}") + `,"scope":"openid"}`, true},
		{"empty-scope", strings.TrimSuffix(valid, "}") + `,"scope":""}`, false},
		{"expanded-scope", strings.TrimSuffix(valid, "}") + `,"scope":"openid administrator"}`, false},
		{"duplicate-scope", strings.TrimSuffix(valid, "}") + `,"scope":"openid openid"}`, false},
		{"wrong-type", strings.Replace(valid, `"expires_in":60`, `"expires_in":"60"`, 1), false},
		{"fraction", strings.Replace(valid, `"expires_in":60`, `"expires_in":0.5`, 1), false},
		{"negative", strings.Replace(valid, `"expires_in":60`, `"expires_in":-1`, 1), false},
		{"overflow", strings.Replace(valid, `"expires_in":60`, `"expires_in":999999999999999999999999999999999`, 1), false},
		{"zero", strings.Replace(valid, `"expires_in":60`, `"expires_in":0`, 1), false},
		{"expiry-upper-bound", strings.Replace(valid, `"expires_in":60`, `"expires_in":31536000`, 1), true},
		{"expiry-too-large", strings.Replace(valid, `"expires_in":60`, `"expires_in":31536001`, 1), false},
		{"escaped-duplicate", `{"access_token":"a","\u0061ccess_token":"b"}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"invalid-utf8", "{\"x\":\"" + string([]byte{0xff}) + "\"}", false},
		{"unpaired-surrogate", `{"x":"\ud800"}`, false},
		{"depth", `{"x":` + strings.Repeat("[", 17) + `0` + strings.Repeat("]", 17) + `}`, false},
		{"many-elements", `{"x":[` + strings.Repeat("0,", 1000) + `0]}`, false},
		{"long-string", `{"x":"` + strings.Repeat("a", 16385) + `"}`, false},
		{"extension", strings.TrimSuffix(valid, "}") + `,"extension":{"nested":[true,null,1,"value"]}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, kind := parseResponse(200, "application/json", []byte(tc.body), parserConfig(), false)
			defer parsed.clear()
			if (kind == "") != tc.valid {
				t.Fatalf("unexpected parser outcome %q", kind)
			}
			if tc.name == "subset" && (!parsed.scopeReported || strings.Join(parsed.scopes, " ") != "openid") {
				t.Fatal("reported scope subset lost")
			}
			if tc.name == "valid" && (parsed.scopeReported || strings.Join(parsed.scopes, " ") != "openid profile") {
				t.Fatal("omitted scope not explicitly preserved")
			}
		})
	}
	fields := make(map[string]any, 257)
	for i := range 257 {
		fields[fmt.Sprint(i)] = nil
	}
	body, _ := json.Marshal(fields)
	if _, kind := parseResponse(200, "application/json", body, parserConfig(), false); kind == "" {
		t.Fatal("too many object members accepted")
	}
}

func FuzzTokenResponse(f *testing.F) {
	for _, seed := range []string{`{}`, `{"error":"invalid_grant"}`, `{"access_token":"a","id_token":"i","token_type":"Bearer","expires_in":60}`, `{"a":1,"a":2}`, `{"x":[true,null,{"a":"b"}]}`, `{"x":"\ud800"}`} {
		f.Add([]byte(seed), uint16(200))
	}
	for _, scope := range []string{"openid https://www.googleapis.com/auth/userinfo.profile", "openid profile https://www.googleapis.com/auth/userinfo.profile", "openid https://www.googleapis.com/auth/userinfo.email"} {
		seed := fmt.Sprintf(`{"access_token":"a","id_token":"i","token_type":"Bearer","expires_in":60,"scope":%q}`, scope)
		f.Add([]byte(seed), uint16(200))
	}
	f.Fuzz(func(t *testing.T, body []byte, status uint16) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		for _, googleAccounts := range []bool{false, true} {
			parsed, kind := parseResponse(int(status), "application/json", body, parserConfig(), googleAccounts)
			defer parsed.clear()
			if kind == "" {
				if status != 200 || len(parsed.access) == 0 || len(parsed.access) > 16<<10 || len(parsed.id) == 0 || len(parsed.id) > 16<<10 || parsed.expires <= 0 || parsed.expires > 31536000 || !validScopes(parsed.scopes) {
					t.Fatal("unbounded successful parse")
				}
				for _, scope := range parsed.scopes {
					if !slices.Contains(parserConfig().Scopes, scope) {
						t.Fatal("returned permission exceeds the requested set")
					}
				}
			}
		}
	})
}

func FuzzPKCEVerifier(f *testing.F) {
	for _, seed := range []string{"", strings.Repeat("x", 43), strings.Repeat("~", 128), strings.Repeat("a", 129), " spaces "} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 {
			t.Skip()
		}
		verifier, err := NewPKCEVerifier(value)
		if err != nil {
			return
		}
		defer verifier.Destroy()
		if len(verifier.Challenge()) != 43 || len(value) < 43 || len(value) > 128 {
			t.Fatal("invalid verifier admitted")
		}
		verifier.Destroy()
		if verifier.Challenge() != "" {
			t.Fatal("destroyed verifier remains usable")
		}
	})
}
