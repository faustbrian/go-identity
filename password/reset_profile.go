package password

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidReset denies invalid configuration, intent or authenticated scope
// without disclosing account, credential, callback or capability material.
var ErrInvalidReset = errors.New("password: invalid reset")

// ResetProfileConfig is trusted, explicit emailed-reset composition. Lifetime
// is a positive whole-second duration at most one hour. Callbacks is an exact
// HTTPS allowlist (1..32 entries, at most 2048 bytes each). Binding keys are
// nonzero 32-byte keys indexed by positive versions (1..16 retained versions).
// The current version must be retained. NewResetProfile copies all inputs;
// callers must not mutate them concurrently with construction. Keys protect
// private callback intent, not the capability signature, and must not be logged.
type ResetProfileConfig struct {
	Issuer, Audience         string
	MaximumLifetime          time.Duration
	Callbacks                []string
	CurrentBindingKeyVersion uint32
	RetainedBindingKeys      map[uint32][32]byte
}

// ResetGrantSpec is original, trusted issuance intent, not client-selected
// account authority. IDs are preserved byte-for-byte, bounded to 128 visible
// ASCII bytes; their canonical admission belongs to the identity owner. All
// versions must be positive, and OriginCommandID must be canonical. Times are
// positive UTC whole seconds; expiry must fit the explicit profile lifetime.
// Only RecoveryPathEmail is supported by this emailed-reset profile. Current
// account/factor/risk eligibility must be checked independently by the workflow.
// FactorVersion is the independent MFA generation authenticated at issuance.
// Zero preserves historical unbound payload bytes, not proof of no factors;
// native factor-fenced completion must reject such historical grants.
type ResetGrantSpec struct {
	TenantID                                                            identity.TenantID
	UserID                                                              identity.UserID
	CredentialID                                                        identity.CredentialID
	CredentialVersion, CredentialAuthorityVersion, UserAuthorityVersion uint64
	IdentifierID                                                        identity.IdentifierID
	IdentifierVersion                                                   uint64
	FactorVersion                                                       uint64
	OriginCommandID                                                     identity.CommandID
	RecoveryPath                                                        auth.RecoveryPath
	CallbackURL                                                         string
	IssuedAt, ExpiresAt                                                 time.Time
}

// ResetProfile freezes a closed emailed-reset capability policy. Copies share
// immutable state and are concurrent-safe. Zero denies. It performs no IO,
// callbacks, clock sampling, consumption, persistence or session issuance.
// Signature verification remains capability.Service's responsibility; protected
// one-time use and current-state checks belong to the coordinated transaction.
type ResetProfile struct{ state *resetProfileState }
type resetProfileState struct {
	issuer, audience string
	lifetime         time.Duration
	callbacks        map[string]struct{}
	current          uint32
	keys             map[uint32][32]byte
}

// NewResetProfile validates and freezes trusted policy without IO or callbacks.
// Issuer is HTTPS without userinfo/query/fragment, bounded to 256 bytes;
// audience is 1..256 visible ASCII bytes. Invalid inputs return ErrInvalidReset.
func NewResetProfile(c ResetProfileConfig) (ResetProfile, error) {
	if !resetHTTPS(c.Issuer, 256) || !resetVisible(c.Audience, 256) || c.MaximumLifetime <= 0 || c.MaximumLifetime > time.Hour || c.MaximumLifetime%time.Second != 0 || len(c.Callbacks) < 1 || len(c.Callbacks) > 32 || len(c.RetainedBindingKeys) < 1 || len(c.RetainedBindingKeys) > 16 || c.CurrentBindingKeyVersion == 0 {
		return ResetProfile{}, ErrInvalidReset
	}
	u, _ := url.Parse(c.Issuer)
	if u.RawQuery != "" || u.ForceQuery {
		return ResetProfile{}, ErrInvalidReset
	}
	s := &resetProfileState{issuer: c.Issuer, audience: c.Audience, lifetime: c.MaximumLifetime, callbacks: make(map[string]struct{}, len(c.Callbacks)), current: c.CurrentBindingKeyVersion, keys: make(map[uint32][32]byte, len(c.RetainedBindingKeys))}
	for _, callback := range c.Callbacks {
		if !resetHTTPS(callback, 2048) {
			return ResetProfile{}, ErrInvalidReset
		}
		if _, ok := s.callbacks[callback]; ok {
			return ResetProfile{}, ErrInvalidReset
		}
		s.callbacks[callback] = struct{}{}
	}
	for version, key := range c.RetainedBindingKeys {
		if version == 0 || key == ([32]byte{}) {
			return ResetProfile{}, ErrInvalidReset
		}
		s.keys[version] = key
	}
	if _, ok := s.keys[s.current]; !ok {
		return ResetProfile{}, ErrInvalidReset
	}
	return ResetProfile{state: s}, nil
}

// Payload returns original closed issuance scope with no grant ID. The durable
// capability issuer selects that ID and signs with its own reviewed engine.
// This does not authorize issuance or mutation. Callback intent is a keyed,
// domain-separated digest; no clear callback is included in bearer material.
func (p ResetProfile) Payload(s ResetGrantSpec) (capability.Payload, error) {
	if p.state == nil {
		return capability.Payload{}, ErrInvalidReset
	}
	return p.payload(s, p.state.current)
}

func (p ResetProfile) payload(s ResetGrantSpec, version uint32) (capability.Payload, error) {
	if p.state == nil || !resetVisible(string(s.TenantID), 128) || !resetVisible(string(s.UserID), 128) || !resetVisible(string(s.CredentialID), 128) || !resetVisible(string(s.IdentifierID), 128) || s.CredentialVersion == 0 || s.CredentialAuthorityVersion == 0 || s.UserAuthorityVersion == 0 || s.IdentifierVersion == 0 || s.RecoveryPath != auth.RecoveryPathEmail || !resetSecond(s.IssuedAt) || !resetSecond(s.ExpiresAt) || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > p.state.lifetime {
		return capability.Payload{}, ErrInvalidReset
	}
	if _, err := identity.ParseCommandID(string(s.OriginCommandID)); err != nil {
		return capability.Payload{}, ErrInvalidReset
	}
	if _, ok := p.state.callbacks[s.CallbackURL]; !ok {
		return capability.Payload{}, ErrInvalidReset
	}
	key, ok := p.state.keys[version]
	if !ok {
		return capability.Payload{}, ErrInvalidReset
	}
	h := hmac.New(sha256.New, key[:])
	_, _ = io.WriteString(h, "golib.identity.password.reset.callback.v1\x00")
	_, _ = io.WriteString(h, s.CallbackURL)
	payload := capability.Payload{Version: 1, Issuer: p.state.issuer, Audiences: []string{p.state.audience}, Subject: string(s.UserID), Resource: "identity.password/" + string(s.CredentialID), Operation: "identity.password.reset-complete", IssuedAt: s.IssuedAt, NotBefore: s.IssuedAt, ExpiresAt: s.ExpiresAt, Tenant: string(s.TenantID), CorrelationID: string(s.OriginCommandID), MaxUses: 1, Caveats: map[string]string{
		"password.recovery-path":                "emailed_password_reset",
		"password.credential-version":           strconv.FormatUint(s.CredentialVersion, 10),
		"password.credential-authority-version": strconv.FormatUint(s.CredentialAuthorityVersion, 10),
		"password.user-authority-version":       strconv.FormatUint(s.UserAuthorityVersion, 10),
		"password.identifier":                   string(s.IdentifierID),
		"password.identifier-version":           strconv.FormatUint(s.IdentifierVersion, 10),
		"password.binding-key-version":          strconv.FormatUint(uint64(version), 10),
		"password.callback":                     hex.EncodeToString(h.Sum(nil)),
	}}
	if s.FactorVersion != 0 {
		payload.Caveats["password.factor-version"] = strconv.FormatUint(s.FactorVersion, 10)
	}
	return payload, nil
}

// Authorize checks a genuinely verified grant against exact original intent
// and the explicit current time. Retained binding keys accept original scope,
// never renewed timestamps. Extra audiences/caveats, unsigned zero grants,
// substitution and expiry deny. Success is scope validation only: it does not
// consume, prove current account eligibility or permit scanner-triggered reset.
func (p ResetProfile) Authorize(g capability.Grant, s ResetGrantSpec, now time.Time) error {
	got := g.Payload()
	version, err := strconv.ParseUint(got.Caveats["password.binding-key-version"], 10, 32)
	if err != nil || now.IsZero() || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || got.ID == "" {
		return ErrInvalidReset
	}
	want, err := p.payload(s, uint32(version))
	if err != nil {
		return ErrInvalidReset
	}
	if got.Version != want.Version || got.Issuer != want.Issuer || len(got.Audiences) != 1 || got.Audiences[0] != want.Audiences[0] || got.Subject != want.Subject || got.Bearer || got.Resource != want.Resource || got.Operation != want.Operation || got.Tenant != want.Tenant || got.CorrelationID != want.CorrelationID || got.MaxUses != 1 || !got.IssuedAt.Equal(want.IssuedAt) || !got.NotBefore.Equal(want.NotBefore) || !got.ExpiresAt.Equal(want.ExpiresAt) || len(got.Caveats) != len(want.Caveats) {
		return ErrInvalidReset
	}
	for key, value := range want.Caveats {
		if got.Caveats[key] != value {
			return ErrInvalidReset
		}
	}
	return nil
}

func resetVisible(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
func resetHTTPS(raw string, maximum int) bool {
	// URL.Parse loses an empty fragment marker; reject its original presence
	// before parsing rather than treating a different callback as canonical.
	if !resetVisible(raw, maximum) || strings.ContainsRune(raw, '#') {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}
func resetSecond(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Nanosecond() == 0
}

// Format redacts reset policy configuration for every diagnostic verb.
func (ResetProfileConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetProfileConfig(redacted)")
}

// MarshalJSON rejects implicit export of reset binding keys and callbacks.
func (ResetProfileConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit export of reset binding keys and callbacks.
func (ResetProfileConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ResetProfileConfig) LogValue() slog.Value {
	return slog.StringValue("password.ResetProfileConfig(redacted)")
}

// Format redacts original reset intent for every diagnostic verb.
func (ResetGrantSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetGrantSpec(redacted)")
}

// MarshalJSON rejects implicit export of original reset intent.
func (ResetGrantSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit export of original reset intent.
func (ResetGrantSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ResetGrantSpec) LogValue() slog.Value {
	return slog.StringValue("password.ResetGrantSpec(redacted)")
}

// Format redacts the immutable reset policy for every diagnostic verb.
func (ResetProfile) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetProfile(redacted)")
}

// MarshalJSON rejects implicit export of the reset policy.
func (ResetProfile) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit export of the reset policy.
func (ResetProfile) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ResetProfile) LogValue() slog.Value { return slog.StringValue("password.ResetProfile(redacted)") }
