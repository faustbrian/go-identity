package passkeyhttp

import (
	"bytes"
	"encoding/json"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passkey "github.com/faustbrian/go-passkey"
)

// Body fields are locators or untrusted intent, never authentication. The native
// owner supplies the tenant, RP, authenticated user and original remember policy.
type requestBody struct {
	flowID, commandID, ceremonyID, proofID string
	identifier, label                      string
	discoverable                           bool
	response                               json.RawMessage
	referenceID, name                      string
	expectedVersion                        uint64
}

func decodeBody(operation string, fields map[string]json.RawMessage) (requestBody, error) {
	var out requestBody
	invalid := func() (requestBody, error) { return requestBody{}, identityhttp.ErrInvalidInput }
	if fields == nil {
		return invalid()
	}
	text := func(name string, destination *string) bool {
		raw, found := fields[name]
		return found && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, destination) == nil
	}
	command := func(name string, destination *string) bool {
		if !text(name, destination) {
			return false
		}
		_, err := identity.ParseCommandID(*destination)
		return err == nil
	}
	allowed := map[string]bool{}
	completion := operation == "register-verify" || operation == "signin-verify"
	switch operation {
	case "update", "delete":
		for _, name := range []string{"proofID", "referenceID", "expectedVersion"} {
			allowed[name] = true
		}
		if !command("proofID", &out.proofID) || !text("referenceID", &out.referenceID) {
			return invalid()
		}
		if _, err := identity.ParseIdentifierID(out.referenceID); err != nil {
			return invalid()
		}
		if operation == "update" {
			allowed["name"] = true
			if !text("name", &out.name) {
				return invalid()
			}
			if _, err := passkey.NewDeviceLabel(out.name); err != nil {
				return invalid()
			}
		}
		raw := bytes.TrimSpace(fields["expectedVersion"])
		if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' || json.Unmarshal(raw, &out.expectedVersion) != nil || out.expectedVersion == 0 || out.expectedVersion == ^uint64(0) {
			return invalid()
		}
	case "register-options", "register-verify":
		allowed["proofID"] = true
		if !command("proofID", &out.proofID) {
			return invalid()
		}
		if completion {
			allowed["label"] = true
			if _, present := fields["label"]; present && (!text("label", &out.label) || len(out.label) > 128 || !utf8.ValidString(out.label)) {
				return invalid()
			}
		}
	case "signin-options", "signin-verify":
		allowed["mode"], allowed["flowID"] = true, true
		var mode string
		if !text("mode", &mode) || !text("flowID", &out.flowID) {
			return invalid()
		}
		if _, err := identity.ParsePreAuthTransactionID(out.flowID); err != nil {
			return invalid()
		}
		switch mode {
		case "identified":
			allowed["identifier"] = true
			if !text("identifier", &out.identifier) || !identifierText(out.identifier) {
				return invalid()
			}
		case "discoverable":
			out.discoverable = true
		default:
			return invalid()
		}
	default:
		return invalid()
	}
	if completion {
		allowed["commandID"], allowed["ceremonyID"], allowed["response"] = true, true, true
		if !command("commandID", &out.commandID) || !command("ceremonyID", &out.ceremonyID) {
			return invalid()
		}
		raw := bytes.TrimSpace(fields["response"])
		if len(raw) < 2 || len(raw) > 262144 || raw[0] != '{' || !json.Valid(raw) || !utf8.Valid(raw) {
			return invalid()
		}
		out.response = fields["response"]
	}
	for name := range fields {
		if !allowed[name] {
			return invalid()
		}
	}
	return out, nil
}

func identifierText(value string) bool {
	if len(value) == 0 || len(value) > 320 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
