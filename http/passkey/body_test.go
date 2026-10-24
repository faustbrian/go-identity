package passkeyhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func bodyFields(t *testing.T, wire string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func FuzzPasskeyHTTPBody(f *testing.F) {
	for _, seed := range []struct {
		mode uint8
		wire string
	}{
		{0, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`},
		{0, `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`},
		{1, `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`},
		{1, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`},
		{2, `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"Straße@faß.de"}`},
		{3, `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`},
		{0, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`},
		{2, `{"mode":"discoverable","userID":"untrusted"}`},
		{4, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":1,"name":"Personal key"}`},
		{5, deleteWire},
		{5, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":18446744073709551615}`},
	} {
		f.Add(seed.mode, seed.wire)
	}
	f.Fuzz(func(t *testing.T, mode uint8, wire string) {
		if len(wire) > 300000 {
			t.Skip()
		}
		decoder, err := identityhttp.NewRequestDecoder(identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 300000, MaximumDecodedBytes: 300000, MaximumFields: 64, MaximumDepth: 8})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(wire))
		r.Header.Set("Content-Type", "application/json")
		fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
		if err != nil {
			return
		}
		operations := []string{"register-options", "register-verify", "signin-options", "signin-verify", "update", "delete"}
		out, err := decodeBody(operations[int(mode)%len(operations)], fields)
		if err == nil && (out.discoverable && out.identifier != "" || out.signup && (out.proofID != "" || out.flowID == "" || out.discoverable) || len(out.response) > 262144 || len(out.label) > 128 || len(out.identifier) > 320) {
			t.Fatal("admitted body escaped fixed bounds/mode")
		}
	})
}

func TestPasskeyBodiesKeepModesAndOriginalCorrelationSeparate(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAQ"
	tests := []struct {
		operation string
		wire      string
	}{
		{"register-options", `{"proofID":"` + id + `"}`},
		{"register-verify", `{"commandID":"` + id + `","ceremonyID":"` + id + `","proofID":"` + id + `","response":{"id":"browser-credential"},"label":"Personal key"}`},
		{"signin-options", `{"mode":"identified","flowID":"` + id + `","identifier":"person@example.invalid"}`},
		{"signin-options", `{"mode":"discoverable","flowID":"` + id + `"}`},
		{"signin-verify", `{"mode":"identified","flowID":"` + id + `","identifier":"person@example.invalid","commandID":"` + id + `","ceremonyID":"` + id + `","response":{"id":"browser-credential"}}`},
		{"signin-verify", `{"mode":"discoverable","flowID":"` + id + `","commandID":"` + id + `","ceremonyID":"` + id + `","response":{"id":"browser-credential"}}`},
	}
	for _, test := range tests {
		t.Run(test.operation+test.wire[:min(22, len(test.wire))], func(t *testing.T) {
			fields := bodyFields(t, test.wire)
			got, err := decodeBody(test.operation, fields)
			if err != nil {
				t.Fatal("selected closed request rejected", err)
			}
			if strings.HasPrefix(test.operation, "signin") {
				if got.flowID != id || got.discoverable != strings.Contains(test.wire, `"discoverable"`) {
					t.Fatal("original flow or selected mode changed")
				}
				if got.discoverable && got.identifier != "" {
					t.Fatal("identifier-free input acquired an identifier")
				}
			}
			if strings.HasSuffix(test.operation, "verify") && (got.commandID != id || got.ceremonyID != id || !bytes.Equal(got.response, fields["response"])) {
				t.Fatal("completion changed original correlation or authenticator bytes")
			}
			for _, field := range []string{"tenantID", "userID", "actorID", "rpID", "remember", "idempotencyKey", "cookie", "csrfToken"} {
				changed := bodyFields(t, test.wire)
				changed[field] = json.RawMessage(`"claimed"`)
				if _, err := decodeBody(test.operation, changed); !errors.Is(err, identityhttp.ErrInvalidInput) {
					t.Fatal("body selected authority or a second transport channel", field)
				}
			}
		})
	}
}

func TestPasskeyBodyRejectsAmbiguousMissingAndOversizedInputs(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAQ"
	tests := []struct {
		operation string
		wire      string
	}{
		{"unknown", `{}`},
		{"register-options", `{}`},
		{"register-options", `{"proofID":null}`},
		{"register-options", `{"proofID":"not-a-command"}`},
		{"register-options", `{"proofID":"` + id + `","commandID":"` + id + `"}`},
		{"register-verify", `{"commandID":"` + id + `","ceremonyID":"` + id + `","proofID":"` + id + `","response":null}`},
		{"register-verify", `{"commandID":"` + id + `","ceremonyID":"` + id + `","proofID":"` + id + `","response":[]}`},
		{"signin-options", `{"flowID":"` + id + `"}`},
		{"signin-options", `{"mode":"conditional","flowID":"` + id + `"}`},
		{"signin-options", `{"mode":"identified","flowID":"` + id + `"}`},
		{"signin-options", `{"mode":"identified","flowID":"` + id + `","identifier":""}`},
		{"signin-options", `{"mode":"identified","flowID":"` + id + `","identifier":"space identifier"}`},
		{"signin-options", `{"mode":"discoverable","flowID":"` + id + `","identifier":"person@example.invalid"}`},
		{"signin-options", `{"mode":"discoverable","flowID":"` + id + `","identifier":null}`},
		{"signin-verify", `{"mode":"discoverable","flowID":"` + id + `","commandID":"` + id + `","ceremonyID":"not-original","response":{}}`},
	}
	for _, test := range tests {
		if _, err := decodeBody(test.operation, bodyFields(t, test.wire)); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("malformed request accepted", test.operation)
		}
	}
	base := `{"commandID":"` + id + `","ceremonyID":"` + id + `","proofID":"` + id + `","response":{}}`
	for _, field := range []string{"label", "response"} {
		fields := bodyFields(t, base)
		if field == "label" {
			fields[field], _ = json.Marshal(strings.Repeat("x", 129))
		} else {
			fields[field] = json.RawMessage(`{"data":"` + strings.Repeat("x", 262144) + `"}`)
		}
		if _, err := decodeBody("register-verify", fields); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("oversized input accepted", field)
		}
	}
}

func TestSignupBodiesRemainDisjointFromEnrollment(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAQ"
	for _, operation := range []string{"register-options", "register-verify"} {
		wire := `{"mode":"signup","flowID":"` + id + `"}`
		if operation == "register-verify" {
			wire = `{"mode":"signup","flowID":"` + id + `","commandID":"` + id + `","ceremonyID":"` + id + `","response":{},"label":"New key"}`
		}
		fields := bodyFields(t, wire)
		out, err := decodeBody(operation, fields)
		if err != nil || !out.signup || out.flowID != id || out.proofID != "" {
			t.Fatal("explicit original-flow signup rejected or changed mode", operation, err)
		}
		for _, name := range []string{"proofID", "identifier", "userID", "email", "password", "remember", "csrfToken", "rpID", "tenantID"} {
			changed := bodyFields(t, wire)
			changed[name] = json.RawMessage(`"untrusted"`)
			if _, err := decodeBody(operation, changed); !errors.Is(err, identityhttp.ErrInvalidInput) {
				t.Fatal("signup accepted enrollment or authority override", name)
			}
		}
		for _, mode := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`"enrollment"`), json.RawMessage(`"discoverable"`), json.RawMessage(`true`)} {
			changed := bodyFields(t, wire)
			changed["mode"] = mode
			if _, err := decodeBody(operation, changed); !errors.Is(err, identityhttp.ErrInvalidInput) {
				t.Fatal("invalid signup mode acquired a fallback")
			}
		}
		delete(fields, "mode")
		if _, err := decodeBody(operation, fields); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("missing signup discriminator acquired enrollment")
		}
	}
}
