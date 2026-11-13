package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"slices"
	"strings"
	"unicode/utf8"
)

type tokenResponse struct {
	access, refresh, id []byte
	expires             int64
	scopes              []string
	scopeReported       bool
}

func (r *tokenResponse) clear() { clear(r.access); clear(r.refresh); clear(r.id) }

func parseResponse(status int, contentType string, body []byte, c OIDCConfig, googleAccounts bool) (tokenResponse, ErrorKind) {
	var out tokenResponse
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "application/json" || len(body) == 0 || int64(len(body)) > c.MaxResponseBytes || !utf8.Valid(body) {
		return out, Unknown
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	budget := 0
	value, err := readJSON(decoder, 0, &budget)
	if err != nil {
		return out, Unknown
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return out, Unknown
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return out, Unknown
	}
	if refusal, present := fields["error"]; present {
		name, ok := refusal.(string)
		if !ok || !slices.Contains([]string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope"}, name) || (status != 400 && status != 401) {
			return out, Unknown
		}
		for _, member := range []string{"access_token", "refresh_token", "id_token", "token_type", "expires_in", "scope"} {
			if _, present := fields[member]; present {
				return out, Unknown
			}
		}
		for _, member := range []string{"error_description", "error_uri"} {
			if value, present := fields[member]; present {
				if _, ok := value.(string); !ok {
					return out, Unknown
				}
			}
		}
		return out, Refused
	}
	if status != 200 {
		return out, Unknown
	}
	for _, member := range []string{"error_description", "error_uri"} {
		if _, present := fields[member]; present {
			return out, Unknown
		}
	}
	access, accessOK := fields["access_token"].(string)
	id, idOK := fields["id_token"].(string)
	kind, kindOK := fields["token_type"].(string)
	expiry, expiryOK := fields["expires_in"].(json.Number)
	if !accessOK || !idOK || !kindOK || !expiryOK || !visible(access, 1, c.MaxTokenBytes) || !visible(id, 1, c.MaxTokenBytes) || !strings.EqualFold(kind, "Bearer") {
		return out, Unknown
	}
	seconds, err := expiry.Int64()
	if err != nil || seconds <= 0 || seconds > 365*24*60*60 {
		return out, Unknown
	}
	refresh := ""
	if value, present := fields["refresh_token"]; present {
		var ok bool
		refresh, ok = value.(string)
		if !ok || !visible(refresh, 1, c.MaxTokenBytes) {
			return out, Unknown
		}
	}
	scopes := slices.Clone(c.Scopes)
	reported := false
	if value, present := fields["scope"]; present {
		raw, ok := value.(string)
		if !ok {
			return out, Unknown
		}
		reportedScopes := strings.Split(raw, " ")
		if !validScopes(reportedScopes) {
			return out, Unknown
		}
		scopes = make([]string, 0, len(reportedScopes))
		for _, scope := range reportedScopes {
			if googleAccounts {
				scope = googleReportedScope(scope, c.Scopes)
			}
			if !slices.Contains(c.Scopes, scope) {
				return out, Unknown
			}
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
		reported = true
	}
	out = tokenResponse{access: []byte(access), refresh: []byte(refresh), id: []byte(id), expires: seconds, scopes: scopes, scopeReported: reported}
	return out, ""
}

// Google can return equivalent scope spellings (developers.google.com/identity/
// protocols/oauth2, "Examine scopes of access granted by the user"). Its identity
// URI scopes have OpenID equivalents (support.google.com/cloud/answer/15549945).
// Map only the two known identity URIs to an actually requested short scope;
// this changes the permission projection, never the original signed token.
func googleReportedScope(scope string, requested []string) string {
	canonical := scope
	switch scope {
	case "https://www.googleapis.com/auth/userinfo.email":
		canonical = "email"
	case "https://www.googleapis.com/auth/userinfo.profile":
		canonical = "profile"
	}
	if slices.Contains(requested, canonical) {
		return canonical
	}
	return scope
}

// Every response member, including ignored OAuth extensions, passes the same
// duplicate/depth/element/string limits. RFC6749 section5.1 permits unknown
// response parameters, not unbounded or ambiguous JSON interpretation.
func readJSON(d *json.Decoder, depth int, budget *int) (any, error) {
	if depth > 16 || *budget >= 1000 {
		return nil, io.ErrUnexpectedEOF
	}
	*budget++
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := map[string]any{}
			for d.More() {
				if len(object) >= 256 {
					return nil, io.ErrUnexpectedEOF
				}
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok || len(name) > 16<<10 || strings.ContainsRune(name, '\ufffd') {
					return nil, io.ErrUnexpectedEOF
				}
				if _, duplicate := object[name]; duplicate {
					return nil, io.ErrUnexpectedEOF
				}
				item, err := readJSON(d, depth+1, budget)
				if err != nil {
					return nil, err
				}
				object[name] = item
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, io.ErrUnexpectedEOF
			}
			return object, nil
		case '[':
			var array []any
			for d.More() {
				item, err := readJSON(d, depth+1, budget)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, io.ErrUnexpectedEOF
			}
			return array, nil
		default:
			return nil, io.ErrUnexpectedEOF
		}
	case string:
		if len(value) > 16<<10 || strings.ContainsRune(value, '\ufffd') {
			return nil, io.ErrUnexpectedEOF
		}
		return value, nil
	case json.Number:
		if len(value) > 32 {
			return nil, io.ErrUnexpectedEOF
		}
		return value, nil
	case nil, bool:
		return value, nil
	default:
		return nil, io.ErrUnexpectedEOF
	}
}
