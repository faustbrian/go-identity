package mfa

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

// TOTPProfile selects an exact stored RFC 6238 profile. Algorithm is one of
// SHA1, SHA256 or SHA512, Digits is 6..10, Period is 15..120 whole seconds and
// AllowedSkewSteps is 0..2 (zero deliberately permits no skew). Issuer is the
// exact 1..128-byte UTF-8 provisioning issuer, without controls, colon or edge
// whitespace. Copy before modification; do not mutate a shared profile during
// verification. Changing a stored profile requires a new enrollment generation.
type TOTPProfile struct {
	Algorithm        string
	Digits           uint32
	Period           time.Duration
	AllowedSkewSteps uint32
	Issuer           string
}

// Validate rejects zero, unsupported or unbounded profiles without IO. It
// returns a redacted identity.InvalidInputError and never repairs or normalizes
// a stored profile implicitly.
func (p TOTPProfile) Validate() error {
	if (p.Algorithm != "SHA1" && p.Algorithm != "SHA256" && p.Algorithm != "SHA512") || p.Digits < 6 || p.Digits > 10 || p.Period < 15*time.Second || p.Period > 120*time.Second || p.Period%time.Second != 0 || p.AllowedSkewSteps > 2 || len(p.Issuer) == 0 || len(p.Issuer) > 128 || !utf8.ValidString(p.Issuer) || strings.TrimSpace(p.Issuer) != p.Issuer {
		return invalidTOTP()
	}
	for _, r := range p.Issuer {
		if unicode.IsControl(r) || r == ':' {
			return invalidTOTP()
		}
	}
	return nil
}

// TOTPReplayState is trusted durable factor metadata, not authentication
// authority. Used distinguishes an unused factor from a used epoch counter.
// The native owner must read it under the same lock as atomic advancement;
// callers must not supply client values or treat Verify as replay consumption.
type TOTPReplayState struct {
	LastStep uint64
	Used     bool
}

// TOTPVerifier is immutable transient cryptographic computation with opaque
// comparison-key custody. Zero denies. Concurrent calls are safe with separate
// secret owners; password.Secret rejects concurrent borrows of the same owner.
// It owns no storage, goroutine, session or clock. Copies retain the key.
type TOTPVerifier struct{ key func() [32]byte }

func invalidTOTP() error { return identity.InvalidInputError{Field: "totp"} }

// NewTOTPVerifier copies a trusted independent, randomly generated comparison
// key; zero is invalid. The key must not derive from a factor secret. Native
// configuration owns its version, rotation and retention. The key is kept
// behind an opaque closure so diagnostic formatting cannot traverse it.
func NewTOTPVerifier(key [32]byte) (TOTPVerifier, error) {
	if key == ([32]byte{}) {
		return TOTPVerifier{}, invalidTOTP()
	}
	return TOTPVerifier{key: func() [32]byte { return key }}, nil
}

// Verify computes a matching moving factor without exposing submitted code or
// retaining factor material. secret is borrowed, never destroyed here: its
// owner must Destroy it after use. Scope is the native owner's injective
// 1..4096-byte tenant/subject/factor/challenge binding including the comparison
// key version. now is authoritative nonnegative Unix time, not client time.
//
// The returned counter is NOT a proof, session permission or durable one-use
// result. Native storage must fence enrollment/authority/policy, spend the
// shared attempt budget and atomically advance replay state with continuation
// completion and session issuance. A mismatch/replay returns ForbiddenError;
// invalid configuration returns InvalidInputError; unavailable secret custody
// returns UnavailableError. Cancellation is preserved. No IO or retry occurs.
func (v TOTPVerifier) Verify(ctx context.Context, secret password.Secret, submitted auth.OneTimeCode, profile TOTPProfile, scope []byte, now time.Time, replay TOTPReplayState) (uint64, error) {
	if ctx == nil || v.key == nil || len(scope) == 0 || len(scope) > 4096 || now.IsZero() || now.Unix() < 0 || (!replay.Used && replay.LastStep != 0) {
		return 0, invalidTOTP()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := profile.Validate(); err != nil {
		return 0, err
	}
	if secret.Len() < 20 || secret.Len() > 128 {
		return 0, identity.UnavailableError{}
	}
	key := v.key()
	defer clear(key[:])
	var step uint64
	var matched bool
	err := secret.Use(func(bytes []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		step, matched = totpOpaqueMatchingStep(bytes, profile.Algorithm, profile.Digits, profile.Period, profile.AllowedSkewSteps, now, replay.LastStep, replay.Used, submitted, key, scope)
		return nil
	})
	if cancellation := ctx.Err(); cancellation != nil {
		return 0, cancellation
	}
	if err != nil {
		return 0, identity.UnavailableError{}
	}
	if !matched {
		return 0, identity.ForbiddenError{}
	}
	return step, nil
}
