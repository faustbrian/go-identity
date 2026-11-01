package oauth

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// QueryCallback is a parsed query success or provider denial, never authenticated
// state, an exchange reservation or identity proof. Copies share terminal secret
// destruction. Its zero value has neither variant. Destroy after bounded native
// processing, including denial and failure; parsing assigns no expiry or TTL.
type QueryCallback struct {
	input   identity.OAuthCallbackInput
	denial  func() *queryDeniedState
	success bool
}

// queryDeniedState owns only denial lookup state; it cannot mint callback/code
// custody or confer native authority. mu owns value and busy.
type queryDeniedState struct {
	mu    sync.Mutex
	value []byte
	busy  bool
}

// ParseQueryCallback parses a raw URL query (without '?') under the exact trusted
// transaction-bound ProviderProfile. Profile, issuer and version must come from
// the native transaction/configuration, never callback-selected data. A caller
// may use bounded raw state to locate that transaction, but must authenticate all
// native bindings, lifetime and one-use admission before exchange or mutation.
// No provider I/O, SQL, state authentication or reservation occurs here.
//
// The selected profile requires code/query/S256, nonce/state32 and RFC9207 iss on
// both success and denial. Exactly one nonempty code or error is required. All
// decoded duplicate names and cross-variant token/JARM responses are rejected.
// RFC6749 section4.1.2 extensions are ignored only after bounded form/UTF-8
// validation. Provider error text/URI/code are validated then deliberately
// discarded: Denied distinguishes refusal without disclosing arbitrary text.
//
// Before decoding, raw input is limited to 3*MaxCodeBytes+16KiB, 32 members,
// 64 decoded bytes per name and bounded encoded values. Decoded limits are the
// profile code limit, 43-byte state, 2048-byte issuer/URI, 256-byte error,
// 1024-byte description and 4096-byte ignored extension. Limits reject, never
// truncate. Nil/malformed profiles/contexts deny; cancellation is Unavailable.
func ParseQueryCallback(ctx context.Context, rawQuery string, profile ProviderProfile) (QueryCallback, error) {
	if ctx == nil || !queryProfileValid(profile) {
		return QueryCallback{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return QueryCallback{}, failure(Unavailable, ctx)
	}
	if len(rawQuery) == 0 || len(rawQuery) > 3*profile.MaxCodeBytes+16*1024 || rawQuery[0] == '?' || strings.ContainsAny(rawQuery, "#") || strings.Count(rawQuery, "&") >= 32 {
		return QueryCallback{}, failure(InvalidInput, ctx)
	}
	// Count and size checks precede Split/decoding; at most 32 bounded entries
	// reach allocation. Decode names first so encoded aliases cannot evade checks.
	seen := make(map[string]bool, 32)
	values := make(map[string][]byte, 6)
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	for _, member := range strings.Split(rawQuery, "&") {
		nameRaw, valueRaw, _ := strings.Cut(member, "=")
		name, ok := queryDecode(nameRaw, 64)
		if !ok || !queryName(name) {
			clear(name)
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		key := string(name)
		clear(name)
		if seen[key] {
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		seen[key] = true
		limit := 4096
		switch key {
		case "code":
			limit = profile.MaxCodeBytes
		case "state":
			limit = 43
		case "iss", "error_uri":
			limit = 2048
		case "error":
			limit = 256
		case "error_description":
			limit = 1024
		case "access_token", "id_token", "token_type", "expires_in", "response":
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		value, ok := queryDecode(valueRaw, limit)
		if !ok {
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		switch key {
		case "code", "state", "iss", "error", "error_description", "error_uri":
			values[key] = value
		default:
			clear(value)
		}
	}
	// RFC9207 section2.4 requires exact decoded string comparison, including
	// error responses. The issuer is not normalized or used to select a provider.
	if string(values["iss"]) != profile.Issuer || !canonical32(string(values["state"])) || seen["code"] == seen["error"] {
		return QueryCallback{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return QueryCallback{}, failure(Unavailable, ctx)
	}
	if seen["code"] {
		if seen["error_description"] || seen["error_uri"] {
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		input, err := identity.NewOAuthCallbackInput(values["code"], string(values["state"]), identity.OAuthCallbackLimits{MaxCodeBytes: profile.MaxCodeBytes, StateBytes: 32})
		if err != nil {
			return QueryCallback{}, failure(InvalidInput, ctx)
		}
		return QueryCallback{input: input, success: true}, nil
	}
	if !queryErrorText(values["error"]) || seen["error_description"] && !queryErrorText(values["error_description"]) || seen["error_uri"] && !queryErrorURI(values["error_uri"]) {
		return QueryCallback{}, failure(InvalidInput, ctx)
	}
	state := make([]byte, len(values["state"]))
	copy(state, values["state"])
	owner := &queryDeniedState{value: state}
	return QueryCallback{denial: func() *queryDeniedState { return owner }}, nil
}

func queryProfileValid(p ProviderProfile) bool {
	if !identifier(p.ID) || p.Version == 0 || !httpsURL(p.Issuer) || !httpsURL(p.AuthorizationEndpoint) || !httpsURL(p.TokenEndpoint) || !httpsURL(p.RedirectURI) || !visible(p.ClientID, 1, 1024) || (p.ClientAuthentication != PublicClient && p.ClientAuthentication != ClientSecretBasic) || !validScopes(p.Scopes) || !slices.Contains(p.Scopes, "openid") || len(p.Algorithms) < 1 || len(p.Algorithms) > 2 || p.ResponseMode != "query" || p.PKCEMethod != "S256" || !p.NonceRequired || p.StateBytes != 32 || p.NonceBytes != 32 || p.Timeout < time.Second || p.Timeout > 30*time.Second || p.ClockSkew <= 0 || p.ClockSkew > 5*time.Minute || p.MaxResponseBytes < 1024 || p.MaxResponseBytes > 1<<20 || p.MaxTokenBytes < 256 || p.MaxTokenBytes > 16<<10 || p.MaxCodeBytes < 1 || p.MaxCodeBytes > 64<<10 {
		return false
	}
	for i, alg := range p.Algorithms {
		if alg != "ES256" && alg != "RS256" || i > 0 && alg == p.Algorithms[0] {
			return false
		}
	}
	return true
}

// queryDecode checks both encoded and decoded lengths before allocation, then
// applies RFC6749 Appendix B form decoding once. No raw data enters errors.
func queryDecode(raw string, limit int) ([]byte, bool) {
	if len(raw) > 3*limit {
		return nil, false
	}
	length := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return nil, false
		}
		if raw[i] == '%' {
			if i+2 >= len(raw) || queryHex(raw[i+1]) == 0xff || queryHex(raw[i+2]) == 0xff {
				return nil, false
			}
			i += 2
		}
		length++
		if length > limit {
			return nil, false
		}
	}
	value := make([]byte, length)
	for i, j := 0, 0; i < len(raw); i, j = i+1, j+1 {
		switch raw[i] {
		case '%':
			value[j] = queryHex(raw[i+1])<<4 | queryHex(raw[i+2])
			i += 2
		case '+':
			value[j] = ' '
		default:
			value[j] = raw[i]
		}
	}
	if !utf8.Valid(value) {
		clear(value)
		return nil, false
	}
	return value, true
}

// queryHex returns a nibble, or 0xff (outside the valid nibble range).
func queryHex(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		return 0xff
	}
}

func queryName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' {
			continue
		}
		return false
	}
	return true
}

func queryErrorText(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

func queryErrorURI(value []byte) bool {
	if !queryErrorText(value) || strings.ContainsRune(string(value), ' ') {
		return false
	}
	raw := string(value)
	u, err := url.Parse(raw)
	if err != nil || strings.Count(raw, "#") > 1 {
		return false
	}
	// net/url intentionally accepts browser-compatible path characters beyond
	// RFC3986. Enforce Appendix A's URI-reference grammar before discarding the
	// URI; brackets belong only to an authority IP literal, not path/query text.
	authorityStart, authorityEnd := -1, -1
	rest := raw
	if u.Scheme != "" {
		rest = raw[len(u.Scheme)+1:]
	}
	if strings.HasPrefix(rest, "//") {
		authorityStart = len(raw) - len(rest) + 2
		authorityEnd = len(raw)
		if end := strings.IndexAny(raw[authorityStart:], "/?#"); end >= 0 {
			authorityEnd = authorityStart + end
		}
		if at := strings.LastIndexByte(raw[authorityStart:authorityEnd], '@'); at >= 0 {
			authorityStart += at + 1
		}
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("-._~:/?#@!$&'()*+,;=", b) >= 0 {
			continue
		}
		if b == '%' {
			if i+2 >= len(value) || queryHex(value[i+1]) == 0xff || queryHex(value[i+2]) == 0xff {
				return false
			}
			i += 2
			continue
		}
		if (b == '[' || b == ']') && i >= authorityStart && i < authorityEnd && strings.HasPrefix(u.Host, "[") {
			continue
		}
		return false
	}
	return true
}

// Input returns the original root code/state custody only for success. The bool
// identifies the parsed variant, not its liveness or native authentication.
func (q QueryCallback) Input() (identity.OAuthCallbackInput, bool) { return q.input, q.success }

// Denied distinguishes a coherent issuer-bound provider error from malformed
// input. It does not authenticate the provider or native state. Provider-supplied
// text is not exposed. Variant metadata remains readable after Destroy.
func (q QueryCallback) Denied() bool { return q.denial != nil }

// UseDeniedState lends one exact private state copy synchronously for native
// transaction lookup/auditing only, never admission or proof. The consumer must
// retain neither bytes nor copies or use them asynchronously. It must enforce
// native expiry, authentication and auditing policy independently. Zero/success,
// destroyed, nil, cancelled, concurrent and reentrant borrows deny. No callback
// runs under a lock; admitted borrows survive Destroy and clear on all exits.
// Panics are suppressed; consumer error classification survives redacted errors.
func (q QueryCallback) UseDeniedState(ctx context.Context, consume func(context.Context, []byte) error) (err error) {
	if ctx == nil || consume == nil || q.denial == nil {
		return failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return failure(Unavailable, ctx)
	}
	owner := q.denial()
	owner.mu.Lock()
	if owner.busy || len(owner.value) == 0 {
		owner.mu.Unlock()
		return failure(InvalidInput, ctx)
	}
	owner.busy = true
	value := make([]byte, len(owner.value))
	copy(value, owner.value)
	owner.mu.Unlock()
	completed := false
	defer func() {
		clear(value)
		owner.mu.Lock()
		owner.busy = false
		owner.mu.Unlock()
		if !completed {
			_ = recover()
			err = failure(InvalidInput, ctx)
		}
	}()
	cause := consume(ctx, value)
	completed = true
	if cause != nil {
		return queryStateCause(func() error { return cause })
	}
	return nil
}

type queryStateCause func() error

func (queryStateCause) Error() string   { return "oauth: denied state use failed" }
func (c queryStateCause) Unwrap() error { return c() }

// Destroy clears retained success or denial state across aliases. It is
// idempotent and safe during a borrow; no asynchronous work is started or awaited.
func (q QueryCallback) Destroy() {
	q.input.Destroy()
	if q.denial == nil {
		return
	}
	owner := q.denial()
	owner.mu.Lock()
	clear(owner.value)
	owner.value = nil
	owner.mu.Unlock()
}

// Format redacts all callback diagnostics.
func (QueryCallback) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.QueryCallback(redacted)"))
}

// MarshalJSON refuses accidental callback transport or persistence.
func (QueryCallback) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental callback text/map-key export.
func (QueryCallback) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
