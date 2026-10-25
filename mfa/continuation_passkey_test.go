package mfa_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func passkeyContinuationFixture(t *testing.T) mfa.ContinuationSpec {
	t.Helper()
	s := continuationFixture(t)
	s.PasskeyCommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
	s.PrimaryProofID = auth.ProofID(s.PasskeyCommandID)
	s.AllowedMethods = []string{"totp"}
	return s
}

func TestContinuationPasskeyOriginalAuthenticatesExactSignedCorrelation(t *testing.T) {
	s := passkeyContinuationFixture(t)
	c, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.CapabilityPayload("https://issuer.test")
	if err != nil || payload.CorrelationID != string(s.PasskeyCommandID) || payload.ID != string(s.ID) || payload.MaxUses != 1 || !payload.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("child lost original passkey command or lifetime", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: payload.Issuer, ID: "test-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	verified := func(p capability.Payload) capability.Grant {
		t.Helper()
		token, err := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{Issuer: payload.Issuer, Now: s.IssuedAt, Limits: capability.DefaultLimits()})
		if err != nil {
			t.Fatal(err)
		}
		return grant
	}
	grant := verified(payload)
	for range 2 {
		if err := c.Authorize(grant, payload.Issuer, s.IssuedAt); err != nil {
			t.Fatal("actual signed original passkey child denied or consumed", err)
		}
	}
	for name, correlation := range map[string]string{"missing": "", "foreign": "AgICAgICAgICAgICAgICAg", "child": string(s.ID)} {
		t.Run(name, func(t *testing.T) {
			bad := payload
			bad.CorrelationID = correlation
			if c.Authorize(verified(bad), payload.Issuer, s.IssuedAt) == nil {
				t.Fatal("valid signature bypassed exact original correlation")
			}
		})
	}
	withoutOrigin := s
	withoutOrigin.PasskeyCommandID = ""
	legacy, err := mfa.NewPartialAuthContinuation(withoutOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Authorize(grant, payload.Issuer, s.IssuedAt) == nil {
		t.Fatal("legacy primary implicitly acquired passkey authority")
	}
	oldDigest, err := c.ScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	next, err := c.RecordAttempt("totp", s.IssuedAt.Add(time.Second), 1)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := next.ScopeDigest()
	if err != nil || digest != oldDigest || next.Authorize(grant, payload.Issuer, s.IssuedAt.Add(time.Second)) != nil {
		t.Fatal("factor attempt changed original scope or renewed proof", err)
	}
}

func TestContinuationPasskeyOriginRejectsAmbiguousOrWidenedProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*mfa.ContinuationSpec){
		"malformed": func(s *mfa.ContinuationSpec) { s.PasskeyCommandID = "malformed" },
		"child": func(s *mfa.ContinuationSpec) {
			s.PasskeyCommandID = identity.CommandID(s.ID)
			s.PrimaryProofID = auth.ProofID(s.ID)
		},
		"different-primary": func(s *mfa.ContinuationSpec) { s.PrimaryProofID = "AgICAgICAgICAgICAgICAg" },
		"mixed-origins":     func(s *mfa.ContinuationSpec) { s.VerificationCommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"otp":               func(s *mfa.ContinuationSpec) { s.AllowedMethods = []string{"otp"} },
		"recovery":          func(s *mfa.ContinuationSpec) { s.AllowedMethods = []string{"totp", "recovery-code"} },
	} {
		t.Run(name, func(t *testing.T) {
			s := passkeyContinuationFixture(t)
			mutate(&s)
			if _, err := mfa.NewPartialAuthContinuation(s); err == nil {
				t.Fatal("invalid explicit passkey profile accepted")
			}
		})
	}
}
