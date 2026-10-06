package risk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// ErrInvalidCaptchaReplay rejects malformed or foreign replay preparation.
// It never identifies which secret, provider or flow field failed.
var ErrInvalidCaptchaReplay = errors.New("risk: invalid captcha replay")

// FlowKind selects one closed trusted server context, not authentication proof.
type FlowKind string

const (
	// FlowPreAuth binds a subject or anonymous flow to a pre-auth transaction.
	FlowPreAuth FlowKind = "pre-auth"
	// FlowAuthenticated binds an authenticated subject and its exact session.
	FlowAuthenticated FlowKind = "authenticated"
	// FlowAdministrator binds an independently authenticated administrative actor.
	FlowAdministrator FlowKind = "administrator"
)

// FlowContextInput is trusted server-resolved issuance scope, never HTTP input.
// Exactly one of Subject and AnonymousFlow is required. Pre-auth requires only
// PreAuthTransaction; authenticated requires Subject and Session; administrator
// requires Actor and permits its independently verified Session. ChallengeID
// and canonical 32-byte RequestFingerprint bind one exact intended issuance.
// Structural admission does not authenticate identities or grant permission.
type FlowContextInput struct {
	Kind                                                       FlowKind
	Tenant                                                     string
	Operation                                                  Action
	Subject, AnonymousFlow, PreAuthTransaction, Session, Actor string
	ChallengeID, RequestFingerprint                            string
}

// FlowContext freezes closed trusted flow metadata for core-owned preparation.
// Zero is invalid; immutable copies are safe for concurrent reads. The eventual
// issuance coordinator must independently authorize and recheck this context.
type FlowContext struct{ state *flowContextState }
type flowContextState struct{ input FlowContextInput }

// NewFlowContext validates exact canonical operation membership and closed
// context dimensions without IO, clocks or authorization callbacks.
func NewFlowContext(in FlowContextInput) (FlowContext, error) {
	if len(in.Operation) == 0 || len(in.Operation) > 128 {
		return FlowContext{}, ErrInvalidCaptchaReplay
	}
	if _, ok := canonicalOperations[in.Operation]; !ok || !scopeID(in.Tenant) || !scopeID(in.ChallengeID) || (in.Subject == "") == (in.AnonymousFlow == "") {
		return FlowContext{}, ErrInvalidCaptchaReplay
	}
	for _, id := range []string{in.Subject, in.AnonymousFlow, in.PreAuthTransaction, in.Session, in.Actor} {
		if id != "" && !scopeID(id) {
			return FlowContext{}, ErrInvalidCaptchaReplay
		}
	}
	if len(in.RequestFingerprint) != 43 {
		return FlowContext{}, ErrInvalidCaptchaReplay
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(in.RequestFingerprint)
	if err != nil || len(digest) != 32 {
		return FlowContext{}, ErrInvalidCaptchaReplay
	}
	switch in.Kind {
	case FlowPreAuth:
		if in.PreAuthTransaction == "" || in.Session != "" || in.Actor != "" {
			return FlowContext{}, ErrInvalidCaptchaReplay
		}
	case FlowAuthenticated:
		if in.Subject == "" || in.Session == "" || in.PreAuthTransaction != "" || in.Actor != "" {
			return FlowContext{}, ErrInvalidCaptchaReplay
		}
	case FlowAdministrator:
		if in.Actor == "" || in.PreAuthTransaction != "" {
			return FlowContext{}, ErrInvalidCaptchaReplay
		}
	default:
		return FlowContext{}, ErrInvalidCaptchaReplay
	}
	return FlowContext{state: &flowContextState{input: in}}, nil
}

// CaptchaReplayKey owns a copied versioned 32..128-byte replay HMAC secret.
// Zero is invalid; copies share immutable private storage. Go cannot guarantee
// erasure. This key is distinct from provider credentials or counter secrets.
type CaptchaReplayKey struct {
	version uint32
	secret  []byte
}

// NewCaptchaReplayKey copies nonempty versioned secret custody without IO.
func NewCaptchaReplayKey(version uint32, secret []byte) (CaptchaReplayKey, error) {
	if version == 0 || len(secret) < 32 || len(secret) > 128 {
		return CaptchaReplayKey{}, ErrInvalidPolicy
	}
	return CaptchaReplayKey{version: version, secret: slices.Clone(secret)}, nil
}

// CaptchaReplayPolicyConfig is immutable selected server configuration. Keys
// are 1..16 unique newest-first retained versions; no version referenced by an
// unresolved issuance or retained tombstone may be omitted. Site is 1..512 UTF-8
// bytes; APIProfile is the exact 1..128-byte ASCII profile ID, not a protocol
// availability claim. ConfigurationVersion is 1..64 ASCII bytes. MaxTokenBytes
// is explicitly 1..8192. This selects no provider, risk or storage fallback.
type CaptchaReplayPolicyConfig struct {
	Policy                                           Policy
	Provider, Site, APIProfile, ConfigurationVersion string
	MaxTokenBytes                                    int
	Keys                                             []CaptchaReplayKey
}

// CaptchaReplayPolicy owns bounded pure derivation, not provider verification,
// an issuance decision or one-use authority. Zero is invalid; configured values
// are copied and concurrency-safe. Core imports no provider or durable adapter.
type CaptchaReplayPolicy struct{ state *captchaReplayPolicyState }
type captchaReplayPolicyState struct{ config CaptchaReplayPolicyConfig }

// NewCaptchaReplayPolicy validates the exact selected scope and retained keys
// without callbacks or hashing. The provider must be one supported closed ID;
// its later adapter separately validates the actual protocol/API capability.
func NewCaptchaReplayPolicy(c CaptchaReplayPolicyConfig) (CaptchaReplayPolicy, error) {
	if c.Policy.state == nil || c.MaxTokenBytes < 1 || c.MaxTokenBytes > 8192 || len(c.Keys) < 1 || len(c.Keys) > 16 || len(c.Site) < 1 || len(c.Site) > 512 || !utf8.ValidString(c.Site) || strings.TrimSpace(c.Site) != c.Site || strings.ContainsRune(c.Site, 0) || !scopeID(c.APIProfile) || len(c.ConfigurationVersion) > 64 || !scopeID(c.ConfigurationVersion) {
		return CaptchaReplayPolicy{}, ErrInvalidPolicy
	}
	switch c.Provider {
	case "recaptcha", "turnstile", "hcaptcha", "captchafox":
	default:
		return CaptchaReplayPolicy{}, ErrInvalidPolicy
	}
	for i, k := range c.Keys {
		if k.version == 0 || len(k.secret) < 32 || len(k.secret) > 128 || i > 0 && c.Keys[i-1].version <= k.version {
			return CaptchaReplayPolicy{}, ErrInvalidPolicy
		}
	}
	c.Keys = slices.Clone(c.Keys)
	return CaptchaReplayPolicy{state: &captchaReplayPolicyState{config: c}}, nil
}

// CaptchaReplayDigest is explicit native storage metadata, never HTTP output.
// Fingerprint is the canonical 43-byte unpadded base64url HMAC; Version belongs
// to retained secret custody and is not included in the prescribed MAC bytes.
type CaptchaReplayDigest struct {
	Version     uint32
	Fingerprint string
}

// CaptchaReplayBinding is an owned adapter-only lookup projection. The durable
// namespace is Flow.Tenant + provider/site/profile/configuration + fingerprint;
// flow, action, command and tenant do not enter the protocol's replay MAC.
// All Keys name one logical token, not independent issuance opportunities.
// Native storage must validate rotation history and acquire one winner across
// every retained alias before issuing. This metadata grants no such authority.
type CaptchaReplayBinding struct {
	Flow                                             FlowContextInput
	Provider, Site, APIProfile, ConfigurationVersion string
	Keys                                             []CaptchaReplayDigest
}

// CaptchaReplayIdentity is opaque immutable core preparation provenance. It
// retains no raw token. Copies are safe for concurrent reads; zero is invalid.
// Bindings is a restricted native projection, not provider or public evidence.
type CaptchaReplayIdentity struct{ state *captchaReplayIdentityState }
type captchaReplayIdentityState struct {
	owner   *captchaReplayPolicyState
	binding CaptchaReplayBinding
}

// Prepare bounds raw secret UTF-8 bytes before hashing and never trims, parses
// or retains them. Exact selected operation policy must require CAPTCHA. The
// same provider token/config/key has identical replay identity across commands,
// actions, flows and tenants; each preparation separately retains its exact
// trusted flow. No provider call, state transition, clock or permission occurs.
func (p CaptchaReplayPolicy) Prepare(flow FlowContext, token []byte) (CaptchaReplayIdentity, error) {
	if p.state == nil || flow.state == nil {
		return CaptchaReplayIdentity{}, ErrInvalidCaptchaReplay
	}
	c := p.state.config
	in := flow.state.input
	a, err := c.Policy.Admit(in.Operation)
	if err != nil || a.Preflight != "" || !slices.Contains(a.Profile.RequiredSignals, "captcha") || len(token) == 0 || len(token) > c.MaxTokenBytes || !utf8.Valid(token) {
		return CaptchaReplayIdentity{}, ErrInvalidCaptchaReplay
	}
	b := CaptchaReplayBinding{Flow: in, Provider: c.Provider, Site: c.Site, APIProfile: c.APIProfile, ConfigurationVersion: c.ConfigurationVersion, Keys: make([]CaptchaReplayDigest, len(c.Keys))}
	for i, key := range c.Keys {
		mac := hmac.New(sha256.New, key.secret)
		_, _ = io.WriteString(mac, "identity-captcha-replay-v1\x00")
		for _, field := range []string{c.Provider, c.Site, c.APIProfile, c.ConfigurationVersion} {
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(len(field)))
			_, _ = mac.Write(size[:])
			_, _ = io.WriteString(mac, field)
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(token)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(token)
		b.Keys[i] = CaptchaReplayDigest{Version: key.version, Fingerprint: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
	}
	return CaptchaReplayIdentity{state: &captchaReplayIdentityState{owner: p.state, binding: b}}, nil
}

// Validate checks original preparing policy and exact trusted flow without
// accepting a reconstructed fingerprint, rederiving bytes or granting use.
func (p CaptchaReplayPolicy) Validate(identity CaptchaReplayIdentity, flow FlowContext) error {
	if p.state == nil || identity.state == nil || flow.state == nil || identity.state.owner != p.state || identity.state.binding.Flow != flow.state.input {
		return ErrInvalidCaptchaReplay
	}
	return nil
}

// Bindings returns an independently owned native projection; zero returns empty
// metadata. Mutating it cannot change the immutable identity or validate it.
func (i CaptchaReplayIdentity) Bindings() CaptchaReplayBinding {
	if i.state == nil {
		return CaptchaReplayBinding{}
	}
	b := i.state.binding
	b.Keys = slices.Clone(b.Keys)
	return b
}

// Format redacts trusted flow metadata from automatic diagnostics.
func (FlowContextInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.FlowContextInput(redacted)")
}

// MarshalJSON forbids automatic flow export.
func (FlowContextInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids automatic flow export.
func (FlowContextInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts retained flow custody.
func (FlowContext) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.FlowContext(redacted)")
}

// MarshalJSON forbids automatic flow export.
func (FlowContext) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids automatic flow export.
func (FlowContext) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts key material.
func (CaptchaReplayKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayKey(redacted)")
}

// MarshalJSON forbids secret export.
func (CaptchaReplayKey) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids secret export.
func (CaptchaReplayKey) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts keys and selected configuration.
func (CaptchaReplayPolicyConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayPolicyConfig(redacted)")
}

// MarshalJSON forbids runtime custody export.
func (CaptchaReplayPolicyConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids runtime custody export.
func (CaptchaReplayPolicyConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts retained runtime custody.
func (CaptchaReplayPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayPolicy(redacted)")
}

// MarshalJSON forbids runtime custody export.
func (CaptchaReplayPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids runtime custody export.
func (CaptchaReplayPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts reusable replay digests.
func (CaptchaReplayDigest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayDigest(redacted)")
}

// MarshalJSON forbids replay-digest export.
func (CaptchaReplayDigest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids replay-digest export.
func (CaptchaReplayDigest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts native lookup and flow metadata.
func (CaptchaReplayBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayBinding(redacted)")
}

// MarshalJSON forbids replay projection export.
func (CaptchaReplayBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids replay projection export.
func (CaptchaReplayBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts native preparation custody.
func (CaptchaReplayIdentity) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayIdentity(redacted)")
}

// MarshalJSON forbids preparation custody export.
func (CaptchaReplayIdentity) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids preparation custody export.
func (CaptchaReplayIdentity) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
