package mfa_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func continuationFixture(t *testing.T) mfa.ContinuationSpec {
	t.Helper()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 18, 0, 0, 0, time.UTC)
	return mfa.ContinuationSpec{ID: "AAAAAAAAAAAAAAAAAAAAAQ", PrimaryProofID: auth.ProofID("primary-proof"), PrimaryProofDigest: [32]byte{1}, PrimaryProofExpiresAt: now.Add(3 * time.Minute), TenantID: "tenant", SubjectID: identity.SubjectID("subject"), SourcePreAuthID: "bbbbbbbbbbbbbbbbbbbbbg", Origin: "https://app.test", AllowedMethods: []string{"totp", "recovery-code"}, PolicyVersion: 3, FactorVersion: 7, RememberPolicy: remember, Purpose: "identity.mfa.complete", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1}
}

func TestContinuationVerificationParentIsImmutableSignedScope(t *testing.T) {
	legacy := continuationFixture(t)
	original, err := mfa.NewPartialAuthContinuation(legacy)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, _ := original.ScopeDigest()
	// Captured before passkey-origin support: adding another optional origin must
	// not invalidate already issued password/magic-link capabilities.
	if hex.EncodeToString(oldDigest[:]) != "3bcc5c63f603be28e4af4ae079092a29b35b9858d18b10c52429c250a201266b" {
		t.Fatal("legacy immutable-scope bytes changed")
	}
	oldPayload, _ := original.CapabilityPayload("https://issuer.test")
	if oldPayload.CorrelationID != "" {
		t.Fatal("legacy continuation acquired verification origin")
	}
	legacy.VerificationCommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	selected, err := mfa.NewPartialAuthContinuation(legacy)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := selected.ScopeDigest()
	payload, _ := selected.CapabilityPayload("https://issuer.test")
	if digest == oldDigest || payload.CorrelationID != string(legacy.VerificationCommandID) || payload.ExpiresAt != oldPayload.ExpiresAt || payload.ID != oldPayload.ID {
		t.Fatal("verification discriminator lost scope binding or renewed child")
	}
	after, err := selected.RecordAttempt("totp", legacy.IssuedAt.Add(time.Second), 1)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest, _ := after.ScopeDigest()
	if afterDigest != digest {
		t.Fatal("attempt changed immutable verification origin")
	}
	for _, id := range []identity.CommandID{identity.CommandID(legacy.ID), identity.CommandID(legacy.PrimaryProofID), "malformed"} {
		s := legacy
		s.VerificationCommandID = id
		if _, err := mfa.NewPartialAuthContinuation(s); err == nil {
			t.Fatal("self/primary/malformed verification origin accepted")
		}
	}
}

func TestContinuationAuthenticatesFullOriginalCapabilityScopeReadOnly(t *testing.T) {
	spec := continuationFixture(t)
	c, err := mfa.NewPartialAuthContinuation(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.CapabilityPayload("https://issuer.test")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := c.ScopeDigest()
	if err != nil || payload.Caveats["mfa.scope"] != hex.EncodeToString(digest[:]) {
		t.Fatal("store and signed scope disagree", err)
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
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://issuer.test", ID: "test-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	verified := func(p capability.Payload) capability.Grant {
		t.Helper()
		token, err := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{Issuer: "https://issuer.test", Now: spec.IssuedAt, Limits: capability.DefaultLimits()})
		if err != nil {
			t.Fatal(err)
		}
		return grant
	}
	grant := verified(payload)
	for range 3 {
		if err := c.Authorize(grant, payload.Issuer, spec.IssuedAt); err != nil {
			t.Fatal("read-only validation consumed original grant", err)
		}
	}
	if c.Authorize(capability.Grant{}, payload.Issuer, spec.IssuedAt) == nil || c.Authorize(grant, "https://foreign.test", spec.IssuedAt) == nil || c.Authorize(grant, payload.Issuer, spec.ExpiresAt) == nil {
		t.Fatal("zero/foreign/expired grant accepted")
	}
	for _, change := range []func(*mfa.ContinuationSpec){
		func(s *mfa.ContinuationSpec) { s.PrimaryProofExpiresAt = s.PrimaryProofExpiresAt.Add(time.Second) },
		func(s *mfa.ContinuationSpec) { s.TenantID = "foreign" }, func(s *mfa.ContinuationSpec) { s.SubjectID = "foreign" }, func(s *mfa.ContinuationSpec) { s.PolicyVersion++ }, func(s *mfa.ContinuationSpec) { s.FactorVersion++ }, func(s *mfa.ContinuationSpec) { s.PrimaryProofID = "other-proof" }, func(s *mfa.ContinuationSpec) { s.PrimaryProofDigest[0]++ }, func(s *mfa.ContinuationSpec) { s.Origin = "https://foreign.test" }, func(s *mfa.ContinuationSpec) { s.Audience = "foreign" }, func(s *mfa.ContinuationSpec) { s.MaxAttempts++; s.AttemptsRemaining++ }, func(s *mfa.ContinuationSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) }, func(s *mfa.ContinuationSpec) { s.AllowedMethods = []string{"totp"} },
		func(s *mfa.ContinuationSpec) {
			s.RememberPolicy, _ = session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
		},
	} {
		s := continuationFixture(t)
		change(&s)
		other, err := mfa.NewPartialAuthContinuation(s)
		if err != nil {
			t.Fatal("invalid substitution fixture", err)
		}
		if other.Authorize(grant, payload.Issuer, spec.IssuedAt) == nil {
			t.Fatal("bound original scope was substituted")
		}
	}
	for _, change := range []func(*capability.Payload){
		func(p *capability.Payload) { p.MaxUses = 0 }, func(p *capability.Payload) { p.Caveats["extra"] = "extension" }, func(p *capability.Payload) { p.ID = "other" }, func(p *capability.Payload) { p.Operation = "identity.mfa.step-up" }, func(p *capability.Payload) { p.Audiences = append(p.Audiences, "foreign") },
	} {
		p, _ := c.CapabilityPayload(payload.Issuer)
		change(&p)
		if c.Authorize(verified(p), payload.Issuer, spec.IssuedAt) == nil {
			t.Fatal("widened or alternate signed payload accepted")
		}
	}
	next, err := c.RecordAttempt("totp", spec.IssuedAt.Add(time.Second), 1)
	if err != nil || next.Authorize(grant, payload.Issuer, spec.IssuedAt.Add(time.Second)) != nil {
		t.Fatal("attempt invalidated immutable original binding", err)
	}
}

func TestContinuationConservesScopeAndSharedAttemptBudget(t *testing.T) {
	spec := continuationFixture(t)
	c, err := mfa.NewPartialAuthContinuation(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.AllowedMethods[0] = "otp"
	owned, err := c.Bindings()
	if err != nil || strings.Join(owned.AllowedMethods, ",") != "recovery-code,totp" {
		t.Fatal("caller altered original methods", err)
	}
	owned.AllowedMethods[0] = "otp"
	payload, err := c.CapabilityPayload("https://issuer.test")
	if err != nil || payload.MaxUses != 1 || payload.ID != "AAAAAAAAAAAAAAAAAAAAAQ" || payload.Subject != "subject" || payload.Tenant != "tenant" {
		t.Fatal("unbound continuation profile", err)
	}
	for i, method := range []string{"totp", "recovery-code", "totp"} {
		c, err = c.RecordAttempt(method, continuationFixture(t).IssuedAt.Add(time.Second), uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := c.Bindings()
		if got.AttemptsRemaining != uint32(2-i) || got.Version != uint64(i+2) {
			t.Fatal("switching methods reset attempt budget")
		}
		current, e := c.CapabilityPayload("https://issuer.test")
		a, _ := capability.CanonicalPayload(payload, capability.DefaultLimits())
		b, _ := capability.CanonicalPayload(current, capability.DefaultLimits())
		if e != nil || string(a) != string(b) {
			t.Fatal("attempt renewed or changed original capability scope", e)
		}
	}
	terminal, _ := c.Bindings()
	if terminal.State != mfa.Revoked || c.RequirePending(terminal.IssuedAt.Add(time.Second)) == nil {
		t.Fatal("exhaustion is not terminal")
	}
	var ended mfa.ContinuationTerminalError
	if !errors.As(c.RequirePending(terminal.IssuedAt.Add(time.Second)), &ended) || ended.State != mfa.Revoked {
		t.Fatal("exhaustion lost typed terminal disposition")
	}
	if _, err := c.RecordAttempt("totp", terminal.IssuedAt.Add(time.Second), terminal.Version); err == nil {
		t.Fatal("terminal continuation admitted another attempt")
	}
}

func TestContinuationRejectsInvalidStateAndAttemptSubstitution(t *testing.T) {
	spec := continuationFixture(t)
	c, err := mfa.NewPartialAuthContinuation(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method  string
		at      time.Time
		version uint64
	}{{"otp", spec.IssuedAt, 1}, {"totp", spec.IssuedAt, 2}, {"totp", spec.ExpiresAt, 1}, {"totp", spec.IssuedAt.Add(-time.Second), 1}} {
		if _, err := c.RecordAttempt(test.method, test.at, test.version); err == nil {
			t.Fatal("foreign/stale/expired attempt accepted")
		}
	}
	var conflict mfa.ContinuationConflictError
	_, err = c.RecordAttempt("totp", spec.IssuedAt, 2)
	if !errors.As(err, &conflict) {
		t.Fatal("stale continuation version lost typed conflict")
	}
	var expired mfa.ContinuationTerminalError
	if !errors.As(c.RequirePending(spec.ExpiresAt), &expired) || expired.State != mfa.Expired {
		t.Fatal("absolute expiry lost terminal disposition")
	}
	for _, mutate := range []func(*mfa.ContinuationSpec){
		func(s *mfa.ContinuationSpec) { s.PrimaryProofExpiresAt = s.IssuedAt.Add(time.Minute) },
		func(s *mfa.ContinuationSpec) { s.State = 0 }, func(s *mfa.ContinuationSpec) { s.PolicyVersion = 0 }, func(s *mfa.ContinuationSpec) { s.FactorVersion = 0 }, func(s *mfa.ContinuationSpec) { s.AllowedMethods = []string{"totp", "totp"} }, func(s *mfa.ContinuationSpec) { s.AllowedMethods = []string{"password"} }, func(s *mfa.ContinuationSpec) { s.RememberPolicy = session.RememberPolicy{} }, func(s *mfa.ContinuationSpec) { s.ExpiresAt = s.IssuedAt.Add(6 * time.Minute) }, func(s *mfa.ContinuationSpec) { s.AttemptsRemaining = 0 }, func(s *mfa.ContinuationSpec) { s.PrimaryProofDigest = [32]byte{} }, func(s *mfa.ContinuationSpec) { s.MaxAttempts = 101 },
	} {
		s := continuationFixture(t)
		mutate(&s)
		if _, err := mfa.NewPartialAuthContinuation(s); err == nil {
			t.Fatal("invalid continuation produced usable state")
		}
	}
	for _, value := range []any{spec, c} {
		if strings.Contains(fmt.Sprintf("%+v", value), "primary-proof") {
			t.Fatal("continuation disclosed original proof identity")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("continuation serialized as transport authority")
		}
		if text, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("missing text redaction")
		} else if _, err := text.MarshalText(); err == nil {
			t.Fatal("continuation exported as text")
		}
		if strings.Contains(slog.AnyValue(value).Resolve().String(), "primary-proof") {
			t.Fatal("structured log disclosed primary proof identity")
		}
	}
	if (mfa.PartialAuthContinuation{}).RequirePending(spec.IssuedAt) == nil {
		t.Fatal("zero continuation admitted")
	}
}
