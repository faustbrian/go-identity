package oauth

import "encoding/json"

// Called only after the unchanged bounded token parser established a known
// refusal with no token fields, duplicates or invalid JSON. Keep this stricter
// refresh-only interpretation separate from existing exchange error behavior.
func refreshRefusal(status int, raw []byte) ErrorKind {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return Unknown
	}
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	var code string
	if json.Unmarshal(fields["error"], &code) != nil {
		return Unknown
	}
	// RFC6749 section5.2 allows 401 only for invalid_client. Other errors use
	// 400; a contradictory status must not destroy a possibly rotated grant.
	if status != 400 && (status != 401 || code != "invalid_client") {
		return Unknown
	}
	for _, member := range []string{"error_description", "error_uri"} {
		value, present := fields[member]
		if !present {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return Unknown
		}
		if text == "" {
			continue
		}
		if member == "error_description" {
			if !queryErrorText([]byte(text)) {
				return Unknown
			}
		} else if !queryErrorURI([]byte(text)) {
			return Unknown
		}
	}
	if code == "invalid_grant" {
		return RefreshGrantRejected
	}
	return Refused
}
