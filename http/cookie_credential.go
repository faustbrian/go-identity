package identityhttp

import (
	"net/http"
	"strings"

	"github.com/faustbrian/go-authentication"
)

// CookieBearer acquires only the exact case-sensitive selected cookie into
// authentication's existing opaque bearer custody. This is not authentication:
// the owning workflow must validate its token format and original possession.
// Authorization and Proxy-Authorization are forbidden; query values never
// substitute for cookies, and a selected-name query alternative is rejected.
//
// Name is a 1..128-byte HTTP token. Requirement applies to this cookie, not
// unrelated cookies. All Cookie lines share at most 16KiB and 32 parts; each
// part has a valid name and RFC6265 cookie-octet value. Malformed siblings deny.
// The selected part must be unique, unquoted, nonempty, at most 3800 bytes
// including its name and '=', and match the bounded bearer token grammar.
// Values are never trimmed, decoded or normalized. Header envelope limits may
// impose stricter bounds. Every error returns zero custody and false.
//
// The decoder owns no request/resource and performs no IO, body reads or token
// comparison. Independent requests may share it; requests must not be mutated
// concurrently. Route owners still forbid body/redirect alternatives and apply
// network/origin/CSRF policy before domain work. Parsed headers cannot establish
// their original proxy/network provenance.
func (d *RequestDecoder) CookieBearer(r *http.Request, name string, requirement HeaderRequirement) (authentication.BearerCredential, bool, error) {
	return d.cookieBearer(r, name, requirement, false)
}

// AuxiliaryCookieBearer acquires exact auxiliary cookie custody only alongside
// one syntactically valid direct Authorization bearer. It does not authenticate
// either input: callers validate the original primary credential and auxiliary
// provenance with their respective owners. Never use the returned cookie as a
// session credential or fallback. Proxy-Authorization and query alternatives
// deny. All CookieBearer framing, limits, cancellation and zero-on-error rules
// apply unchanged; this method never mutates headers or accesses the body.
// Existing CookieBearer retains its no-Authorization exclusivity.
func (d *RequestDecoder) AuxiliaryCookieBearer(r *http.Request, name string, requirement HeaderRequirement) (authentication.BearerCredential, bool, error) {
	if _, _, err := d.Bearer(r, HeaderRequired); err != nil {
		return authentication.BearerCredential{}, false, err
	}
	return d.cookieBearer(r, name, requirement, true)
}

func (d *RequestDecoder) cookieBearer(r *http.Request, name string, requirement HeaderRequirement, auxiliary bool) (authentication.BearerCredential, bool, error) {
	var zero authentication.BearerCredential
	if len(name) > 128 || !credentialCookieName(name) {
		return zero, false, ErrInvalidInput
	}
	if err := d.credentialEnvelope(r, requirement); err != nil {
		return zero, false, err
	}
	for header := range r.Header {
		if (!auxiliary && strings.EqualFold(header, "Authorization")) || strings.EqualFold(header, "Proxy-Authorization") {
			return zero, false, DecodeError{}
		}
	}
	query, err := d.parameters(r.URL.RawQuery)
	if err != nil {
		return zero, false, err
	}
	for key := range query {
		if foldName(key) == foldName(name) {
			return zero, false, DecodeError{}
		}
	}
	count, total := 0, 0
	selected, found := "", false
	for key, values := range r.Header {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		if len(values) == 0 {
			return zero, false, DecodeError{}
		}
		for _, raw := range values {
			if raw == "" || len(raw) > 16384-total {
				return zero, false, DecodeError{}
			}
			total += len(raw)
			for {
				part, remainder, more := strings.Cut(raw, ";")
				count++
				if count > 32 {
					return zero, false, DecodeError{}
				}
				// Delimiter whitespace precedes the next cookie name. Trailing
				// whitespace belongs to the value and must fail cookie-octet
				// validation rather than silently selecting different bytes.
				part = strings.TrimLeft(part, " \t")
				n, v, ok := strings.Cut(part, "=")
				if !ok || !credentialCookieName(n) {
					return zero, false, DecodeError{}
				}
				quoted := len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"'
				if quoted {
					v = v[1 : len(v)-1]
				}
				for i := range len(v) {
					b := v[i]
					if !(b == 0x21 || b >= 0x23 && b <= 0x2b || b >= 0x2d && b <= 0x3a || b >= 0x3c && b <= 0x5b || b >= 0x5d && b <= 0x7e) {
						return zero, false, DecodeError{}
					}
				}
				if n == name {
					if found || quoted || len(part) > 3800 || !bearerToken(v) {
						return zero, false, DecodeError{}
					}
					selected, found = v, true
				}
				if !more {
					break
				}
				raw = remainder
			}
		}
	}
	if found && requirement == HeaderForbidden || !found && requirement == HeaderRequired {
		return zero, false, DecodeError{}
	}
	if err := r.Context().Err(); err != nil {
		return zero, false, err
	}
	if !found {
		return zero, false, nil
	}
	return authentication.NewBearerCredential(selected), true, nil
}

func credentialCookieName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b <= 32 || b >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b)) {
			return false
		}
	}
	return true
}
