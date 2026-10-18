// Package otp owns purpose-bound one-time challenges. Code generation and
// profile policy are available; durable issue/attempt/consume workflows are in
// development. Generated codes and prechecks alone grant no authority.
package otp

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrInvalidProfile means a zero or unsupported code policy. It includes no input.
	ErrInvalidProfile = errors.New("otp: invalid code profile")
	// ErrInvalidGeneration means missing generation context or callback.
	ErrInvalidGeneration = errors.New("otp: invalid generation")
	// ErrGenerationUnavailable means entropy failure or the bounded sampler exhausted.
	ErrGenerationUnavailable = errors.New("otp: generation unavailable")
	// ErrCodeUse means the bounded code callback failed. Its error is deliberately
	// not retained: a renderer/provider error may contain the raw code.
	ErrCodeUse = errors.New("otp: code callback failed")
)

// Purpose is the closed workflow purpose. Zero and unregistered values are
// invalid. It is policy, not evidence of authorization or a verified challenge.
type Purpose string

const (
	// PurposeSignin authenticates an existing account.
	PurposeSignin Purpose = "signin"
	// PurposeEmailVerification proves the exact issued email-address binding.
	PurposeEmailVerification Purpose = "email-verification"
	// PurposePhoneVerification proves the exact issued SMS phone binding. It
	// cannot authorize email verification, account signin or password recovery.
	PurposePhoneVerification Purpose = "phone-verification"
	// PurposePasswordReset permits the exact issued password-recovery workflow.
	PurposePasswordReset Purpose = "password-reset"
	// PurposeEmailChange confirms the exact issued address change.
	PurposeEmailChange Purpose = "email-change"
	// PurposeMFA completes the exact issued multifactor challenge.
	PurposeMFA Purpose = "mfa"
	// PurposeStepUp completes the exact issued protected-action step-up.
	PurposeStepUp Purpose = "step-up"
)

// ReplacementPolicy selects challenge retention upon committed replacement.
// The store must serialize replacement against verification; generation does
// not invalidate an existing code. Zero is invalid.
type ReplacementPolicy uint8

const (
	// ReplacePrevious requires atomic successor enqueue and predecessor revocation.
	ReplacePrevious ReplacementPolicy = iota + 1
	// RetainPrevious preserves earlier issued challenges, under the same family
	// send and attempt limits. It never extends an earlier challenge's expiry.
	RetainPrevious
)

// CodeProfileSpec is explicit policy, with no implicit deployment defaults.
// Alphabet is 2..94 distinct visible ASCII symbols; Length is 4..128 and the
// complete space must contain at least one million possibilities (six decimal
// digits). TTL and ResendInterval are each 30 seconds..10 minutes. MaximumSends
// is 1..10 per hour per tenant/purpose/subject/destination; Attempts is 1..10
// total per challenge across verification methods. Store enforcement remains
// authoritative, not this validation or generation operation.
type CodeProfileSpec struct {
	Purpose        Purpose
	Alphabet       string
	Length         int
	TTL            time.Duration
	ResendInterval time.Duration
	MaximumSends   uint32
	Attempts       uint32
	Replacement    ReplacementPolicy
}

// CodeProfile is immutable validated policy, safe for concurrent use. Zero is
// invalid. It owns no keys, code, store, callback or synchronization resources.
type CodeProfile struct{ spec CodeProfileSpec }

// NewCodeProfile validates before allocation and copies retained alphabet
// bytes. It rejects unknown purpose/replacement policy and insufficient code
// space with ErrInvalidProfile. No IO, hashing or randomness is performed.
func NewCodeProfile(s CodeProfileSpec) (CodeProfile, error) {
	if !validPurpose(s.Purpose) || len(s.Alphabet) < 2 || len(s.Alphabet) > 94 || s.Length < 4 || s.Length > 128 ||
		s.TTL < 30*time.Second || s.TTL > 10*time.Minute || s.ResendInterval < 30*time.Second || s.ResendInterval > 10*time.Minute ||
		s.MaximumSends < 1 || s.MaximumSends > 10 || s.Attempts < 1 || s.Attempts > 10 ||
		(s.Replacement != ReplacePrevious && s.Replacement != RetainPrevious) {
		return CodeProfile{}, ErrInvalidProfile
	}
	var seen [94]bool
	for i := 0; i < len(s.Alphabet); i++ {
		b := s.Alphabet[i]
		if b < 33 || b > 126 || seen[b-33] {
			return CodeProfile{}, ErrInvalidProfile
		}
		seen[b-33] = true
	}
	// Saturating integer arithmetic avoids float threshold errors and overflow
	// for long profiles while exactly admitting the six-decimal-digit baseline.
	space := 1
	for range s.Length {
		space *= len(s.Alphabet)
		if space >= 1_000_000 {
			break
		}
	}
	if space < 1_000_000 {
		return CodeProfile{}, ErrInvalidProfile
	}
	s.Alphabet = strings.Clone(s.Alphabet)
	s.Purpose = Purpose(strings.Clone(string(s.Purpose)))
	return CodeProfile{spec: s}, nil
}

func validPurpose(p Purpose) bool {
	switch p {
	case PurposeSignin, PurposeEmailVerification, PurposePhoneVerification, PurposePasswordReset, PurposeEmailChange, PurposeMFA, PurposeStepUp:
		return true
	default:
		return false
	}
}

// Bindings returns a complete non-secret policy projection. Zero returns
// ErrInvalidProfile. It does not resolve defaults, renew validity or confer
// authentication authority; the returned value is caller-owned.
func (p CodeProfile) Bindings() (CodeProfileSpec, error) {
	if p.spec.Purpose == "" {
		return CodeProfileSpec{}, ErrInvalidProfile
	}
	return p.spec, nil
}
