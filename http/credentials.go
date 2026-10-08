package identityhttp

import (
	"net/http"
	"strings"

	"github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// HeaderRequirement declares whether a route forbids, permits or requires a
// credential header. Zero forbids it. Unknown values are invalid configuration.
// Optional idempotency is reserved for protocol rows explicitly permitting it;
// the router must derive this policy from the selected operation, not the client.
type HeaderRequirement uint8

const (
	// HeaderForbidden rejects presence, including an empty value.
	HeaderForbidden HeaderRequirement = iota
	// HeaderOptional accepts either absence or one valid header.
	HeaderOptional
	// HeaderRequired requires exactly one valid header.
	HeaderRequired
)

// IdempotencyKey copies one exact Idempotency-Key into the kernel's existing
// opaque custody type. It applies the immutable envelope limits, rejects query,
// cookie and trailer alternatives, and never trims or normalizes key bytes.
// The kernel constructor owns the 1..256 ASCII HTTP-token grammar. Absence when
// permitted returns a zero key and false; every error does likewise.
// This method never reads/closes the body, authenticates, hashes or deduplicates.
// The route must also decode its body through the appropriate strict codec;
// ordinary JSON/form codecs reject body alternatives. Multipart and protocol
// codecs must enforce their own equivalent channel checks before domain work.
// Trusted composition must prevent middleware from synthesizing credential
// headers: a parsed Request cannot prove its original network provenance.
func (d *RequestDecoder) IdempotencyKey(r *http.Request, requirement HeaderRequirement) (identity.IdempotencyKey, bool, error) {
	var zero identity.IdempotencyKey
	if err := d.credentialEnvelope(r, requirement); err != nil {
		return zero, false, err
	}
	raw, present, err := selectedHeader(r.Header, "Idempotency-Key", requirement)
	if err != nil || !present {
		return zero, false, err
	}
	if len(raw) == 0 || len(raw) > 256 {
		return zero, false, DecodeError{}
	}
	key, err := identity.NewIdempotencyKey([]byte(raw))
	if err != nil {
		return zero, false, DecodeError{}
	}
	return key, true, nil
}

// Bearer extracts only Authorization into the existing authentication custody
// type; extraction is not credential validation or authorization. The selected
// grammar is case-insensitive Bearer, exactly one ASCII space, then 1..8192
// bytes from letters, digits, '-._~+/' with optional trailing '=' padding.
// At least one non-padding byte is required. Whitespace, commas, controls and
// non-ASCII deny. Envelope header limits may impose a smaller effective bound.
// Cookies are ignored, never a fallback. Proxy-Authorization and query bearer
// alternatives deny. Body and redirect fields never supply bearer authority.
// No body reads, closure, cryptography or domain calls occur. Invalid/absent
// optional input returns the zero credential and false; errors retain no input.
// HeaderForbidden implements the bearer-issue route's Authorization rejection.
// A later trusted-network owner must prove provenance; syntax cannot detect an
// upstream proxy that replaced an otherwise syntactically valid header.
func (d *RequestDecoder) Bearer(r *http.Request, requirement HeaderRequirement) (authentication.BearerCredential, bool, error) {
	var zero authentication.BearerCredential
	if err := d.credentialEnvelope(r, requirement); err != nil {
		return zero, false, err
	}
	if _, present := singleHeader(r.Header, "Proxy-Authorization"); present {
		return zero, false, DecodeError{}
	}
	query, err := d.parameters(r.URL.RawQuery)
	if err != nil {
		return zero, false, err
	}
	for name := range query {
		switch foldName(name) {
		case "access_token", "authorization", "bearer_token":
			return zero, false, DecodeError{}
		}
	}
	raw, present, err := selectedHeader(r.Header, "Authorization", requirement)
	if err != nil || !present {
		return zero, false, err
	}
	scheme, token, separated := strings.Cut(raw, " ")
	if !separated || !strings.EqualFold(scheme, "Bearer") || !bearerToken(token) {
		return zero, false, DecodeError{}
	}
	return authentication.NewBearerCredential(token), true, nil
}

func (d *RequestDecoder) credentialEnvelope(r *http.Request, requirement HeaderRequirement) error {
	if d == nil || !d.valid || r == nil || requirement > HeaderRequired {
		return ErrInvalidInput
	}
	if err := d.envelope(r); err != nil {
		return err
	}
	// Validate raw query independently of cached Form/PostForm. This also
	// rejects escaped/case-alias retry keys without trusting net/http merging.
	if _, err := d.parameters(r.URL.RawQuery); err != nil {
		return err
	}
	for name, values := range r.Header {
		if !strings.EqualFold(name, "Cookie") {
			continue
		}
		for _, value := range values {
			for value != "" {
				part, rest, _ := strings.Cut(value, ";")
				cookieName, _, _ := strings.Cut(strings.TrimSpace(part), "=")
				if forbiddenKeyName(foldName(strings.TrimSpace(cookieName))) {
					return DecodeError{}
				}
				value = rest
			}
		}
	}
	return r.Context().Err()
}

func selectedHeader(headers http.Header, name string, requirement HeaderRequirement) (string, bool, error) {
	value, present := singleHeader(headers, name)
	if present && requirement == HeaderForbidden || !present && requirement == HeaderRequired {
		return "", false, DecodeError{}
	}
	return value, present, nil
}

func bearerToken(token string) bool {
	if len(token) == 0 || len(token) > 8192 || token[0] == '=' {
		return false
	}
	padding := false
	for i := range token {
		c := token[i]
		if c == '=' {
			padding = true
			continue
		}
		if padding || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/", rune(c))) {
			return false
		}
	}
	return true
}
