package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
)

// OIDCClaimProjectionConfig selects exact, case-sensitive top-level ID-token
// names from trusted startup configuration. Names must contain 1..128 ASCII
// bytes, start with a letter or underscore, and otherwise contain only letters,
// digits, underscores, dots or hyphens. Select 1..128 unique names; the count is
// capped at the existing OIDC validator's 128-member bound, not a larger budget.
// There are no wildcards, normalization, nested paths or default selections.
// The exact names nonce, at_hash, c_hash, access_token, refresh_token and id_token
// are forbidden: protocol secrets and token custody are not mapping data.
// A selected value may be absent, null, bool or a string of at most 4096 UTF-8
// bytes. Strings are neither normalized nor truncated; other kinds fail closed.
// Selection never establishes claim authority, membership or authorization.
type OIDCClaimProjectionConfig struct{ Names []string }

// OIDCClaimKind distinguishes selected absence, explicit null and scalar values.
// The empty kind belongs only to an invalid zero VerifiedOIDCClaim.
type OIDCClaimKind string

const (
	// OIDCClaimAbsent means the selected name was not present in the ID token.
	OIDCClaimAbsent OIDCClaimKind = "absent"
	// OIDCClaimNull means the selected name had an explicit JSON null value.
	OIDCClaimNull OIDCClaimKind = "null"
	// OIDCClaimString includes the valid empty string.
	OIDCClaimString OIDCClaimKind = "string"
	// OIDCClaimBool includes the valid false value.
	OIDCClaimBool OIDCClaimKind = "bool"
)

// VerifiedOIDCClaim is a read-only selected observation from the exact validated
// ID token, not an authorization decision. Zero is invalid, not selected absence.
// Explicit getters disclose selected data to its consumer; diagnostics redact it.
type VerifiedOIDCClaim struct {
	name string
	kind OIDCClaimKind
	text string
	flag bool
}

// Name returns the exact configured claim name, or empty for zero.
func (c VerifiedOIDCClaim) Name() string { return c.name }

// Kind returns the selected presence/value kind, or empty for zero.
func (c VerifiedOIDCClaim) Kind() OIDCClaimKind { return c.kind }

// StringValue returns the exact string, including empty, only for a string kind.
func (c VerifiedOIDCClaim) StringValue() (string, bool) { return c.text, c.kind == OIDCClaimString }

// BoolValue returns the exact boolean, including false, only for a bool kind.
func (c VerifiedOIDCClaim) BoolValue() (bool, bool) { return c.flag, c.kind == OIDCClaimBool }

// Format redacts selected claim data from all diagnostic formats.
func (VerifiedOIDCClaim) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.VerifiedOIDCClaim(redacted)"))
}

type oidcClaimProjection struct{ claims []VerifiedOIDCClaim }

// NewOIDCProviderWithClaims opts the strict generic provider into a bounded
// selected-claim projection without changing OIDCConfig or default providers.
// Configuration is snapshotted without I/O. All NewOIDCProvider verification,
// transport, lifetime, concurrency and custody rules remain in effect. Invalid
// selection returns InvalidInput; an unsupported selected value after exchange
// returns InvalidProof with no identity, projected claims or token custody.
func NewOIDCProviderWithClaims(c OIDCConfig, projection OIDCClaimProjectionConfig) (*OIDCProvider, error) {
	if len(projection.Names) < 1 || len(projection.Names) > 128 {
		return nil, failure(InvalidInput, nil)
	}
	seen := make(map[string]bool, len(projection.Names))
	for _, name := range projection.Names {
		if !oidcProjectionName(name) || seen[name] {
			return nil, failure(InvalidInput, nil)
		}
		seen[name] = true
	}
	p, err := NewOIDCProvider(c)
	if err != nil {
		return nil, err
	}
	p.claimNames = slices.Clone(projection.Names)
	return p, nil
}

// VerifiedOIDCClaims returns selected observations in configuration order, with
// absent and null entries retained. The slice is detached; values are immutable.
// Zero, refused and default-provider results return nil. Verification establishes
// the source only: SSO mapping owns per-claim authority and authorization policy.
// No bearer, refresh token, raw ID token or unselected claim map is exposed.
func (r ExchangeResult) VerifiedOIDCClaims() []VerifiedOIDCClaim {
	if r.Identity.oidcClaims == nil {
		return nil
	}
	return slices.Clone(r.Identity.oidcClaims.claims)
}

// Format also protects nested formatting of the private projection owner; fmt
// does not invoke a nested value's Formatter through unexported struct fields.
func (ProviderIdentity) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.ProviderIdentity(redacted)"))
}

func oidcProjectionName(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	switch name {
	case "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token":
		return false
	}
	for index, char := range []byte(name) {
		letter := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		if letter || char == '_' {
			continue
		}
		if index == 0 || !(char >= '0' && char <= '9' || char == '.' || char == '-') {
			return false
		}
	}
	return true
}

// This is projection, never protocol verification. The caller has completed
// strict signature/issuer/audience/time/nonce and optional token/code bindings on
// these exact bytes. That existing validator owns JSON uniqueness, Unicode,
// member/depth limits and the 16KiB token bound; no unvalidated path calls here.
func projectValidatedOIDCClaims(token []byte, names []string) (*oidcClaimProjection, bool) {
	if len(names) == 0 {
		return nil, true
	}
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(string(parts[1]))
	defer clear(payload)
	if err != nil {
		return nil, false
	}
	projection := &oidcClaimProjection{claims: make([]VerifiedOIDCClaim, len(names))}
	for index, name := range names {
		projection.claims[index] = VerifiedOIDCClaim{name: name, kind: OIDCClaimAbsent}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return nil, false
	}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false
		}
		index := slices.Index(names, name.(string))
		if index < 0 {
			clear(raw)
			continue
		}
		claim := &projection.claims[index]
		switch {
		case bytes.Equal(raw, []byte("null")):
			claim.kind = OIDCClaimNull
		case bytes.Equal(raw, []byte("true")), bytes.Equal(raw, []byte("false")):
			claim.kind = OIDCClaimBool
			claim.flag = bytes.Equal(raw, []byte("true"))
		case len(raw) > 0 && raw[0] == '"':
			if json.Unmarshal(raw, &claim.text) != nil || len(claim.text) > 4096 {
				clear(raw)
				return nil, false
			}
			claim.kind = OIDCClaimString
		default:
			clear(raw)
			return nil, false
		}
		clear(raw)
	}
	return projection, true
}
