package risk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// CaptchaEvidenceCustody owns the exact immutable startup verifier, policy and
// retained key configuration for native command authentication. It has no
// executor, provider or clock and cannot prepare, verify or issue new evidence.
// This separates durable-adapter construction from executable issuer wiring;
// neither a dummy executor nor caller-written orchestration is required.
// Copies share immutable owned state and are safe for concurrent calls. Zero
// is invalid. Signature/configuration success never proves current authority,
// replay ownership, commitment, freshness or protected-use permission.
type CaptchaEvidenceCustody struct{ state *captchaEvidenceIssuerState }

// CaptchaReplayKeyIdentity is native-only retention metadata. Commitment is
// HMAC-SHA-256 keyed by the replay secret over the literal domain
// "identity-captcha-replay-key-identity-v1", NUL, and the four-byte big-endian
// version. It authenticates version-to-secret continuity, not a provider token,
// permission or issuance. Version is nonzero; commitments must stay out of
// public responses, logs, metrics and generic serialization.
type CaptchaReplayKeyIdentity struct {
	Version    uint32
	Commitment [32]byte
}

// CaptchaReplayKeyCustody is an independently owned adapter projection of one
// exact provider/site/profile/configuration and its 1..16 newest-first key
// identities. It contains no raw secret, token or token alias. Mutation cannot
// alter startup custody. Zero is invalid; durable owners must retain referenced
// identities and deny omission or replacement rather than infer key retirement.
type CaptchaReplayKeyCustody struct {
	Provider, Site, APIProfile, ConfigurationVersion string
	Keys                                             []CaptchaReplayKeyIdentity
}

// ReplayKeyCustody derives bounded domain-separated key identities without
// callbacks, IO or time. Zero returns ErrInvalidPolicy. This projection lets
// durable adapters reject replacing a retained secret under the same version;
// it grants no replay, command, migration or disclosure authority by itself.
func (c CaptchaEvidenceCustody) ReplayKeyCustody() (CaptchaReplayKeyCustody, error) {
	if c.state == nil {
		return CaptchaReplayKeyCustody{}, ErrInvalidPolicy
	}
	config := c.state.config.Replay.state.config
	out := CaptchaReplayKeyCustody{Provider: config.Provider, Site: config.Site, APIProfile: config.APIProfile, ConfigurationVersion: config.ConfigurationVersion, Keys: make([]CaptchaReplayKeyIdentity, len(config.Keys))}
	for i, key := range config.Keys {
		mac := hmac.New(sha256.New, key.secret)
		_, _ = mac.Write([]byte("identity-captcha-replay-key-identity-v1\x00"))
		var version [4]byte
		binary.BigEndian.PutUint32(version[:], key.version)
		_, _ = mac.Write(version[:])
		out.Keys[i].Version = key.version
		copy(out.Keys[i].Commitment[:], mac.Sum(nil))
	}
	return out, nil
}

// Format redacts restricted replay-key linkage.
func (CaptchaReplayKeyIdentity) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayKeyIdentity(redacted)")
}

// MarshalJSON rejects exporting restricted replay-key linkage.
func (CaptchaReplayKeyIdentity) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects exporting restricted replay-key linkage.
func (CaptchaReplayKeyIdentity) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts restricted replay-key configuration.
func (CaptchaReplayKeyCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaReplayKeyCustody(redacted)")
}

// MarshalJSON rejects exporting restricted replay-key configuration.
func (CaptchaReplayKeyCustody) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects exporting restricted replay-key configuration.
func (CaptchaReplayKeyCustody) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// NewCaptchaEvidenceCustody validates the same static configuration as the
// executable issuer and owns copies of its slices/score policy. Clock, Verify
// and Executor are ignored and not retained; every other field retains the
// issuer's explicit bounds and semantics. It invokes no callbacks, randomness,
// clock or IO. Invalid configuration returns redacted ErrInvalidPolicy. Do not
// mutate supplied configuration concurrently during construction.
func NewCaptchaEvidenceCustody(c CaptchaEvidenceIssuerConfig) (CaptchaEvidenceCustody, error) {
	c.Clock, c.Verify, c.Executor = nil, nil, nil
	s, err := newCaptchaEvidenceIssuer(c, false)
	if err != nil {
		return CaptchaEvidenceCustody{}, err
	}
	return CaptchaEvidenceCustody{state: s.state}, nil
}

// ValidateConfiguration checks the adapter's exact policy version and complete
// retained evidence-key pairs against owned startup custody, order-independent.
// Zero, missing, duplicate or foreign keys return ErrInvalidPolicy. This is
// bounded local comparison, not proof of key-retirement or durable authority.
// The input slice is neither retained nor safe for concurrent caller mutation.
func (c CaptchaEvidenceCustody) ValidateConfiguration(policyVersion uint64, keys []EvidenceKey) error {
	if c.state == nil || policyVersion != c.state.config.Replay.state.config.Policy.state.version || len(keys) != len(c.state.config.Keys) {
		return ErrInvalidPolicy
	}
	for _, expected := range c.state.config.Keys {
		found := false
		for _, key := range keys {
			if key == expected {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidPolicy
		}
	}
	return nil
}

// RestoreCaptchaIssue authenticates the original signed command under the
// exact selected verifier/policy configuration and every retained replay-key
// version. It preserves original aliases, nonce and exclusive times, including
// expired historical custody. It invokes no provider, executor or clock and
// creates no new issuance authority. Invalid input returns a zero issue and
// ErrInvalidEvidenceExecution. Native owners must separately establish current
// authorization, command/generation ownership, commitment and primary expiry.
func (c CaptchaEvidenceCustody) RestoreCaptchaIssue(p PreparedCaptchaEvidence) (CaptchaEvidenceIssue, error) {
	return (CaptchaEvidenceIssuer{state: c.state}).RestoreCaptchaIssue(p)
}

// Format redacts the retained configuration and secret key pairs.
func (CaptchaEvidenceCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceCustody(redacted)")
}

// MarshalJSON rejects secret-bearing startup custody serialization.
func (CaptchaEvidenceCustody) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects secret-bearing startup custody serialization.
func (CaptchaEvidenceCustody) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
