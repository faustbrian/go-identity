package risk

import (
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
