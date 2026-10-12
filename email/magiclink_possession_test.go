package email_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

func magicLinkPossessionFixture(t testing.TB) (email.MagicLinkPossessionConfig, email.MagicLinkPossessionSpec, capability.Payload) {
	t.Helper()
	r, s := registrationVerificationFixture(t)
	c := email.MagicLinkPossessionConfig{Address: r.Address, Issuer: r.Issuer, Audience: "identity", MaximumLifetime: time.Hour, Callbacks: r.Redirects, Version: 9}
	original := email.MagicLinkPossessionSpec{TenantID: s.Binding.TenantID, UserID: identity.UserID(s.Payload.SubjectID), IdentifierID: s.IdentifierID, CanonicalAddress: s.Payload.CanonicalAddress.Record().Value, Callback: s.Payload.Redirect.String(), RequestCommandID: s.Binding.CommandID, FlowID: s.Binding.AnonymousFlowID, FlowBinding: [32]byte{1}, Profile: [32]byte{2}, Supersession: [32]byte{3}, CreationDigest: [32]byte{4}, PolicyVersion: 9, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}
	p := capability.Payload{Version: 1, ID: "original-grant", Issuer: c.Issuer, Audiences: []string{c.Audience}, Subject: string(original.UserID), Tenant: string(original.TenantID), Resource: "identity.magiclink/" + string(original.IdentifierID), Operation: "identity.magic-link.consume", CorrelationID: string(original.RequestCommandID), IssuedAt: original.IssuedAt, NotBefore: original.IssuedAt, ExpiresAt: original.ExpiresAt, MaxUses: 1, Caveats: map[string]string{
		"magiclink.identifier": string(original.IdentifierID), "magiclink.identifier-version": "1", "magiclink.verification-version": "1", "magiclink.identifier-authority-version": "1", "magiclink.user-authority-version": "1", "magiclink.credential-authority-version": "1", "magiclink.factor-version": "1", "magiclink.canonical-email": original.CanonicalAddress, "magiclink.callback": original.Callback, "magiclink.intent": "signup-if-allowed", "magiclink.prospective": "1", "magiclink.flow": original.FlowID, "magiclink.flow-binding": hex.EncodeToString(original.FlowBinding[:]), "magiclink.profile": hex.EncodeToString(original.Profile[:]), "magiclink.supersession": hex.EncodeToString(original.Supersession[:]), "magiclink.creation-digest": hex.EncodeToString(original.CreationDigest[:]), "magiclink.email-policy-version": "9",
	}}
	return c, original, p
}

func possessionGrant(t testing.TB, p capability.Payload) capability.Grant {
	t.Helper()
	key := bytes.Repeat([]byte{18}, 32)
	signer, _ := capability.NewHMACSHA256Signer("mailbox", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	resolver, _ := capability.NewKeySet([]capability.Key{{ID: "mailbox", Verifier: verifier}})
	limits := capability.DefaultLimits()
	limits.MaxCaveats = 18
	wire, err := capability.Issue(context.Background(), p, signer, limits)
	if err != nil {
		t.Fatal("real signing failed", err)
	}
	g, err := capability.Verify(context.Background(), wire, resolver, capability.VerifyOptions{Now: p.IssuedAt, Limits: limits})
	if err != nil {
		t.Fatal("real verification failed", err)
	}
	return g
}

func TestMagicLinkPossessionAcceptsOnlyOriginalProspectiveGrant(t *testing.T) {
	c, original, p := magicLinkPossessionFixture(t)
	policy, err := email.NewMagicLinkPossessionPolicy(c)
	if err != nil || policy.Version() != c.Version {
		t.Fatal("explicit mailbox policy missing", err)
	}
	g := possessionGrant(t, p)
	for _, now := range []time.Time{original.IssuedAt, original.ExpiresAt.Add(-time.Nanosecond)} {
		if err := policy.Authorize(g, original, now); err != nil {
			t.Fatal("original possession denied", err)
		}
	}
	for _, now := range []time.Time{{}, original.IssuedAt.Add(-time.Nanosecond), original.ExpiresAt} {
		if policy.Authorize(g, original, now) == nil {
			t.Fatal("freshness bound lost")
		}
	}
	// Matching input without an authenticated grant cannot establish ownership.
	if policy.Authorize(capability.Grant{}, original, original.IssuedAt) == nil {
		t.Fatal("unsigned ownership admitted")
	}
	for name, mutate := range map[string]func(*email.MagicLinkPossessionSpec){
		"tenant":       func(s *email.MagicLinkPossessionSpec) { s.TenantID = "foreign" },
		"user":         func(s *email.MagicLinkPossessionSpec) { s.UserID = "foreign" },
		"identifier":   func(s *email.MagicLinkPossessionSpec) { s.IdentifierID = "foreign" },
		"address":      func(s *email.MagicLinkPossessionSpec) { s.CanonicalAddress = "other@example.test" },
		"callback":     func(s *email.MagicLinkPossessionSpec) { s.Callback = "https://app.example.test/foreign" },
		"origin":       func(s *email.MagicLinkPossessionSpec) { s.RequestCommandID, _ = identity.NewCommandID() },
		"flow":         func(s *email.MagicLinkPossessionSpec) { s.FlowID = "AQEBAQEBAQEBAQEBAQEBAQ" },
		"flow binding": func(s *email.MagicLinkPossessionSpec) { s.FlowBinding[0]++ },
		"profile":      func(s *email.MagicLinkPossessionSpec) { s.Profile[0]++ },
		"supersession": func(s *email.MagicLinkPossessionSpec) { s.Supersession[0]++ },
		"creation":     func(s *email.MagicLinkPossessionSpec) { s.CreationDigest[0]++ },
		"policy":       func(s *email.MagicLinkPossessionSpec) { s.PolicyVersion++ },
		"issued":       func(s *email.MagicLinkPossessionSpec) { s.IssuedAt = s.IssuedAt.Add(time.Second) },
		"expiry":       func(s *email.MagicLinkPossessionSpec) { s.ExpiresAt = s.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			altered := original
			mutate(&altered)
			if policy.Authorize(g, altered, original.IssuedAt) == nil {
				t.Fatal("substituted original admitted")
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"signin":             func(p *capability.Payload) { p.Caveats["magiclink.intent"] = "signin-only" },
		"existing recipient": func(p *capability.Payload) { delete(p.Caveats, "magiclink.prospective") },
		"password reset":     func(p *capability.Payload) { p.Operation = "identity.password.reset-complete" },
		"verification":       func(p *capability.Payload) { p.Operation = "identity.identifier.verify" },
		"bearer":             func(p *capability.Payload) { p.Bearer = true; p.Subject = "" },
		"reuse":              func(p *capability.Payload) { p.MaxUses = 2 },
		"issuer":             func(p *capability.Payload) { p.Issuer = "https://foreign.example.test" },
		"audience":           func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"extra caveat":       func(p *capability.Payload) { p.Caveats["other-profile"] = "bound" },
		"future factor":      func(p *capability.Payload) { p.Caveats["magiclink.factor-version"] = "2" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := p
			altered.Caveats = maps.Clone(p.Caveats)
			mutate(&altered)
			if policy.Authorize(possessionGrant(t, altered), original, original.IssuedAt) == nil {
				t.Fatal("wrong authenticated profile admitted")
			}
		})
	}
}

func TestMagicLinkPossessionPolicyFreezesConfigurationAndRedacts(t *testing.T) {
	c, original, p := magicLinkPossessionFixture(t)
	policy, err := email.NewMagicLinkPossessionPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	g := possessionGrant(t, p)
	c.Callbacks[0] = "https://foreign.example.test"
	if policy.Authorize(g, original, original.IssuedAt) != nil {
		t.Fatal("caller changed frozen callback policy")
	}
	for _, v := range []any{original, c, *policy, struct {
		policy email.MagicLinkPossessionPolicy
	}{*policy}} {
		if text := fmt.Sprintf("%#v", v); strings.Contains(text, original.CanonicalAddress) || strings.Contains(text, original.Callback) {
			t.Fatal("sensitive diagnostic disclosure")
		}
		if wire, err := json.Marshal(v); err == nil && (bytes.Contains(wire, []byte(original.CanonicalAddress)) || bytes.Contains(wire, []byte(original.Callback))) {
			t.Fatal("implicit sensitive export")
		}
	}
	var zero *email.MagicLinkPossessionPolicy
	if zero.Version() != 0 || zero.Authorize(g, original, original.IssuedAt) == nil {
		t.Fatal("zero policy admitted")
	}
}

func TestMagicLinkPossessionRejectsMalformedPolicyAndOriginal(t *testing.T) {
	c, original, payload := magicLinkPossessionFixture(t)
	for name, change := range map[string]func(*email.MagicLinkPossessionConfig){
		"zero version":        func(c *email.MagicLinkPossessionConfig) { c.Version = 0 },
		"zero address":        func(c *email.MagicLinkPossessionConfig) { c.Address = email.AddressPolicy{} },
		"long issuer":         func(c *email.MagicLinkPossessionConfig) { c.Issuer = strings.Repeat("x", 257) },
		"issuer query":        func(c *email.MagicLinkPossessionConfig) { c.Issuer += "?state=foreign" },
		"issuer credentials":  func(c *email.MagicLinkPossessionConfig) { c.Issuer = "https://user:secret@issuer.test" },
		"empty audience":      func(c *email.MagicLinkPossessionConfig) { c.Audience = "" },
		"long audience":       func(c *email.MagicLinkPossessionConfig) { c.Audience = strings.Repeat("a", 129) },
		"zero lifetime":       func(c *email.MagicLinkPossessionConfig) { c.MaximumLifetime = 0 },
		"fractional lifetime": func(c *email.MagicLinkPossessionConfig) { c.MaximumLifetime = time.Second + time.Nanosecond },
		"long lifetime":       func(c *email.MagicLinkPossessionConfig) { c.MaximumLifetime = 24*time.Hour + time.Second },
		"absent callbacks":    func(c *email.MagicLinkPossessionConfig) { c.Callbacks = nil },
		"duplicate callbacks": func(c *email.MagicLinkPossessionConfig) { c.Callbacks = []string{original.Callback, original.Callback} },
		"many callbacks":      func(c *email.MagicLinkPossessionConfig) { c.Callbacks = make([]string, 33) },
		"long callback":       func(c *email.MagicLinkPossessionConfig) { c.Callbacks = []string{strings.Repeat("a", 2049)} },
		"callback fragment":   func(c *email.MagicLinkPossessionConfig) { c.Callbacks = []string{original.Callback + "#token=secret"} },
		"insecure callback":   func(c *email.MagicLinkPossessionConfig) { c.Callbacks = []string{"http://app.test"} },
	} {
		t.Run(name, func(t *testing.T) {
			altered := c
			change(&altered)
			if p, err := email.NewMagicLinkPossessionPolicy(altered); err == nil || p != nil {
				t.Fatal("malformed explicit policy admitted")
			}
		})
	}
	p, _ := email.NewMagicLinkPossessionPolicy(c)
	g := possessionGrant(t, payload)
	for name, change := range map[string]func(*email.MagicLinkPossessionSpec){
		"long tenant":       func(s *email.MagicLinkPossessionSpec) { s.TenantID = identity.TenantID(strings.Repeat("a", 129)) },
		"long address":      func(s *email.MagicLinkPossessionSpec) { s.CanonicalAddress = strings.Repeat("a", 128<<10) },
		"long callback":     func(s *email.MagicLinkPossessionSpec) { s.Callback = strings.Repeat("a", 128<<10) },
		"invalid command":   func(s *email.MagicLinkPossessionSpec) { s.RequestCommandID = "not-a-command" },
		"invalid flow":      func(s *email.MagicLinkPossessionSpec) { s.FlowID = "not-a-flow" },
		"zero creation":     func(s *email.MagicLinkPossessionSpec) { s.CreationDigest = [32]byte{} },
		"zero flow binding": func(s *email.MagicLinkPossessionSpec) { s.FlowBinding = [32]byte{} },
		"zero profile":      func(s *email.MagicLinkPossessionSpec) { s.Profile = [32]byte{} },
		"zero supersession": func(s *email.MagicLinkPossessionSpec) { s.Supersession = [32]byte{} },
		"fractional time":   func(s *email.MagicLinkPossessionSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		"zero time":         func(s *email.MagicLinkPossessionSpec) { s.IssuedAt = time.Time{} },
		"reversed time":     func(s *email.MagicLinkPossessionSpec) { s.ExpiresAt = s.IssuedAt },
		"overlong grant":    func(s *email.MagicLinkPossessionSpec) { s.ExpiresAt = s.IssuedAt.Add(2 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			altered := original
			change(&altered)
			if p.Authorize(g, altered, original.IssuedAt) == nil {
				t.Fatal("malformed original ownership admitted")
			}
		})
	}
}

func FuzzMagicLinkPossessionUntrustedAddressAndCallback(f *testing.F) {
	c, original, payload := magicLinkPossessionFixture(f)
	p, err := email.NewMagicLinkPossessionPolicy(c)
	if err != nil {
		f.Fatal(err)
	}
	g := possessionGrant(f, payload)
	f.Add(original.CanonicalAddress, original.Callback)
	f.Add("other@example.test", original.Callback)
	f.Add("\x00", "https://app.test/#token=secret")
	f.Add(strings.Repeat("a", 4097), strings.Repeat("a", 2049))
	f.Fuzz(func(t *testing.T, address, callback string) {
		altered := original
		altered.CanonicalAddress, altered.Callback = address, callback
		err := p.Authorize(g, altered, original.IssuedAt)
		if err == nil && (address != original.CanonicalAddress || callback != original.Callback) {
			t.Fatal("untrusted substitution accepted")
		}
		if address == original.CanonicalAddress && callback == original.Callback && err != nil {
			t.Fatal("original ownership denied", err)
		}
	})
}
