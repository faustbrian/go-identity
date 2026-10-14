package identityhttp

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// CSRFError denies missing, ambiguous or noncanonical synchronizer input without
// retaining a credential, field name or owner-parser diagnostic.
type CSRFError struct{}

// Error returns the stable redacted token-channel denial.
func (CSRFError) Error() string { return "identity.http.csrf_denied" }

// CSRFDecoderConfig selects only the unsafe cookie-mutation input profile.
// Origins is a required immutable origin/network owner. FormField is an explicit
// 1..64-byte lowercase ASCII identifier (letters, digits and underscore), with a
// letter first; no default or case alias is accepted. Idempotency-key names are
// reserved. The header channel is exactly X-CSRF-Token. JSON and URL-encoded
// forms are the only supported bodies; multipart/protocol parsers are separate.
type CSRFDecoderConfig struct {
	Origins   *OriginGuard
	FormField string
}

// CSRFDecoder borrows immutable origin/network policy and copies its form name.
// Zero is invalid; independent requests may share it. It owns no credentials,
// keys, session state, goroutines or resources. This is input/origin admission,
// not authentication, token HMAC validation or current-authority admission.
type CSRFDecoder struct {
	origins *OriginGuard
	field   string
}

// NewCSRFDecoder validates the complete input policy without IO. Selected
// feature composition must call this profile only after choosing cookie
// authentication, never infer that mode from attacker-controlled credentials.
func NewCSRFDecoder(config CSRFDecoderConfig) (*CSRFDecoder, error) {
	if config.Origins == nil || config.Origins.network == nil || config.Origins.network.decoder == nil || !csrfField(config.FormField) {
		return nil, ErrInvalidInput
	}
	return &CSRFDecoder{origins: config.Origins, field: strings.Clone(config.FormField)}, nil
}

// DecodeCSRF admits exact origin and exactly one token channel for POST, PUT,
// PATCH or DELETE, then invokes the selected credential owner's parser once.
// Pass session.ParseCSRFToken from the opt-in session integration. The generic
// seam keeps base HTTP independent of optional feature modules; it is not a
// crypto callback, session validator or policy substitute. The trusted parser
// must synchronously copy opaque custody, perform no IO and return boundedly.
// Parser errors are redacted; every error returns zero T and nil form data.
// Cancellation is checked before and after the callback, not by detached work.
//
// Tokens are exactly 43 canonical unpadded base64url bytes encoding 32 bytes.
// Query alternatives, duplicate/case-alias channels and header/form coexistence
// deny, including equal values. Cached Form/PostForm are ignored. URL-encoded
// forms are bounded/read even with a header, and success returns their remaining
// fields with the selected credential removed. JSON requires the header and
// leaves its body unread for the owning strict typed decoder, which must reject
// undeclared body credential fields before domain work. Other media types deny.
//
// The existing network decoder supplies all envelope/form/query limits. Body
// borrowing and blocking-read interruption follow RequestDecoder.Form; nothing
// here closes/drains it or creates a goroutine. The server retains request
// metadata custody throughout decoding. GET/HEAD/OPTIONS, bearer-only routes,
// pre-auth, bound-origin and origin-only flows must use their own profiles;
// passing them here is invalid and does no body/parser work.
//
// Success is NOT a current session proof or lease. The protected operation must
// validate the named-key token against its frozen original and active primary
// session under the same transaction as protected work (RequireCSRF), retaining
// all owner fences and terminal validity checks. This decoder does not enforce
// TokenMaximumAge metadata, renew freshness, consume tokens or issue sessions.
func DecodeCSRF[T any](decoder *CSRFDecoder, request *http.Request, parse func(string) (T, error)) (T, url.Values, error) {
	var zero T
	if decoder == nil || decoder.origins == nil || request == nil || parse == nil {
		return zero, nil, ErrInvalidInput
	}
	switch request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return zero, nil, ErrInvalidInput
	}
	if _, err := decoder.origins.Check(request); err != nil {
		return zero, nil, err
	}
	d := decoder.origins.network.decoder
	query, err := d.Query(request)
	if err != nil {
		return zero, nil, err
	}
	for name := range query {
		if decoder.channelName(name) {
			return zero, nil, CSRFError{}
		}
	}
	wire, header, valid := originHeader(request.Header, "X-CSRF-Token")
	if !valid {
		return zero, nil, CSRFError{}
	}
	var fields url.Values
	if media(request.Header, "application/x-www-form-urlencoded") {
		fields, err = d.Form(request)
		if err != nil {
			return zero, nil, err
		}
		for name := range fields {
			if decoder.channelName(name) && name != decoder.field {
				return zero, nil, CSRFError{}
			}
		}
		value, form := fields[decoder.field]
		if header && form {
			return zero, nil, CSRFError{}
		}
		if form {
			wire = value[0] // bounded Form guarantees one value for each exact name
			delete(fields, decoder.field)
		}
	} else if !media(request.Header, "application/json") {
		return zero, nil, CSRFError{}
	}
	if !canonicalCSRF(wire) {
		return zero, nil, CSRFError{}
	}
	if err := request.Context().Err(); err != nil {
		return zero, nil, err
	}
	token, err := parse(wire)
	if cancellation := request.Context().Err(); cancellation != nil {
		return zero, nil, cancellation
	}
	if err != nil {
		return zero, nil, CSRFError{}
	}
	return token, fields, nil
}

func (d *CSRFDecoder) channelName(name string) bool {
	folded := foldName(name)
	return folded == d.field || folded == "x-csrf-token" || folded == "csrf_token" || folded == "csrftoken" || folded == "csrf-token"
}

func csrfField(field string) bool {
	if len(field) < 1 || len(field) > 64 || field[0] < 'a' || field[0] > 'z' || forbiddenKeyName(field) {
		return false
	}
	for i := range field {
		c := field[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func canonicalCSRF(wire string) bool {
	if len(wire) != 43 || strings.ContainsAny(wire, "\r\n") {
		return false
	}
	var raw [32]byte
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(wire))
	return err == nil && n == len(raw)
}
