package email_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

func registrationVerificationFixture(t testing.TB) (email.RegistrationVerificationConfig, email.RegistrationVerificationSpec) {
	t.Helper()
	profile, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "mailboxes", Version: 3, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	address := email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile, PreserveDisplay: true}
	parser, _ := email.NewAddressParser(address)
	mailbox, err := parser.Parse("User+tag@BÜCHER.example")
	if err != nil {
		t.Fatal(err)
	}
	command, _ := identity.NewCommandID()
	flow, _ := identity.NewPreAuthTransactionID()
	b := identity.CommandBinding{CommandID: command, TenantID: "tenant", AnonymousFlowID: string(flow), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, PolicyID: "signup", PolicyVersion: 2, CorrelationID: string(command)}
	redirect, _ := url.Parse("https://app.example.test/verified?state=selected")
	now := time.Unix(1791637200, 0).UTC()
	c := email.RegistrationVerificationConfig{Address: address, Issuer: "https://issuer.example.test", Audience: "email", MaximumLifetime: time.Hour, Redirects: []string{redirect.String()}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {42}}}
	s := email.RegistrationVerificationSpec{Binding: b, IdentifierID: "01K70ZJ34CWYGBDM2PWQX65QJ5", IdentifierVersion: 1, VerificationVersion: 1, Payload: email.CapabilityPayload{TenantID: b.TenantID, SubjectID: "01K70ZJ34CWYGBDM2PWQX65QJ5", CanonicalAddress: mailbox.Canonical(), Purpose: "identity.identifier.verify", Redirect: *redirect, Version: 1}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	return c, s
}

func registrationGrant(t testing.TB, p capability.Payload) capability.Grant {
	t.Helper()
	key := bytes.Repeat([]byte{9}, 32)
	signer, _ := capability.NewHMACSHA256Signer("signing", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: p.Issuer, ID: "signing", Verifier: verifier}})
	p.ID = "issued-grant"
	wire, err := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("actual capability signing failed", err)
	}
	grant, err := capability.Verify(context.Background(), wire, keys, capability.VerifyOptions{Issuer: p.Issuer, Now: p.IssuedAt, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal("actual capability verification failed", err)
	}
	return grant
}

func TestUsernameRegistrationVerificationKeepsOriginalPurposeBinding(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	p, _ := email.NewRegistrationVerificationPolicy(c)
	legacy, err := p.Payload(s)
	if err != nil {
		t.Fatal(err)
	}
	original := s
	s.Binding.OperationID, s.Binding.SchemaID = "identity.username.signup", "username-signup"
	payload, err := p.Payload(s)
	if err != nil {
		t.Fatal("username registration cannot prepare its real mailbox proof", err)
	}
	if payload.Caveats["email.intent"] == legacy.Caveats["email.intent"] {
		t.Fatal("distinct original signup operations share an intent")
	}
	grant := registrationGrant(t, payload)
	if p.Authorize(grant, s, s.IssuedAt) != nil || p.Authorize(grant, original, s.IssuedAt) == nil {
		t.Fatal("mailbox proof lost its exact original username operation")
	}
	s.Binding.SchemaID = "password-signup"
	if _, err := p.Payload(s); err == nil {
		t.Fatal("mixed origin schema accepted")
	}
}

// EV01: the public email owner must not invent a logged-in session to issue a
// new user's mailbox-ownership grant under the original anonymous signup.
func TestRegistrationVerificationHasDistinctAnonymousOwnership(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	original := s.Binding
	p, err := policy.Payload(s)
	if err != nil || p.ID != "" || p.Subject != string(s.Payload.SubjectID) || p.Tenant != string(s.Binding.TenantID) || p.Resource != string(s.IdentifierID) || p.Operation != "identity.identifier.verify" || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != c.Audience || p.Caveats["email.confirm_operation"] != "identity.email.verification-confirm" {
		t.Fatal("email registration grant is absent or retargeted", err)
	}
	if p.Caveats["session_id"] != "" || p.Caveats["session_version"] != "" || s.Binding != original || s.Binding.UserID != "" {
		t.Fatal("signup borrowed authenticated management authority")
	}
	if bytes.Contains([]byte(fmt.Sprint(p.Caveats)), []byte(s.Payload.CanonicalAddress.Record().Value)) {
		t.Fatal("grant published the mailbox instead of its keyed commitment")
	}
	g := registrationGrant(t, p)
	if policy.Authorize(g, s, s.IssuedAt) != nil || policy.Authorize(g, s, s.ExpiresAt.Add(-time.Nanosecond)) != nil || policy.Authorize(g, s, s.ExpiresAt) == nil {
		t.Fatal("original grant authorization/expiry changed")
	}
	p.Caveats["email.confirm_operation"] = "identity.password.reset"
	p.Audiences[0] = "other"
	if policy.Authorize(g, s, s.IssuedAt) != nil {
		t.Fatal("caller projection mutation widened frozen grant")
	}
}

// EV02: every independently mutable scope/fence is bound, not merely valid.
func TestRegistrationVerificationDeniesSubstitution(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	policy, _ := email.NewRegistrationVerificationPolicy(c)
	private := struct {
		policy email.RegistrationVerificationPolicy
	}{*policy}
	if rendered := fmt.Sprintf("%#v", private); strings.Contains(rendered, "map[") || strings.Contains(rendered, "binding_key") {
		t.Fatal("private enclosing diagnostic traversed retained keys")
	}
	p, _ := policy.Payload(s)
	g := registrationGrant(t, p)
	for _, mutate := range []func(*email.RegistrationVerificationSpec){
		func(s *email.RegistrationVerificationSpec) { s.Binding.TenantID, s.Payload.TenantID = "other", "other" },
		func(s *email.RegistrationVerificationSpec) { s.Payload.SubjectID = "other-user" },
		func(s *email.RegistrationVerificationSpec) { s.IdentifierID = "other-address" },
		func(s *email.RegistrationVerificationSpec) { s.IdentifierVersion++ },
		func(s *email.RegistrationVerificationSpec) { s.VerificationVersion++ },
		func(s *email.RegistrationVerificationSpec) { s.Payload.Version++ },
		func(s *email.RegistrationVerificationSpec) { s.Binding.PolicyVersion++ },
		func(s *email.RegistrationVerificationSpec) { s.Binding.ActorID = "different-ingress" },
		func(s *email.RegistrationVerificationSpec) { s.Binding.AnonymousFlowID = "AgICAgICAgICAgICAgICAg" },
		func(s *email.RegistrationVerificationSpec) { s.Binding.CommandID, _ = identity.NewCommandID() },
		func(s *email.RegistrationVerificationSpec) { s.Payload.Redirect.RawQuery = "state=changed" },
		func(s *email.RegistrationVerificationSpec) { s.Payload.Purpose = "identity.password.reset" },
		func(s *email.RegistrationVerificationSpec) {
			parser, _ := email.NewAddressParser(c.Address)
			changed, _ := parser.Parse("Other@bücher.example")
			s.Payload.CanonicalAddress = changed.Canonical()
		},
		func(s *email.RegistrationVerificationSpec) {
			profile, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "mailboxes", Version: 4, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
			parser, _ := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile})
			changed, _ := parser.Parse("User+tag@bücher.example")
			s.Payload.CanonicalAddress = changed.Canonical()
		},
		func(s *email.RegistrationVerificationSpec) { s.IssuedAt = s.IssuedAt.Add(time.Second) },
		func(s *email.RegistrationVerificationSpec) { s.ExpiresAt = s.ExpiresAt.Add(-time.Second) },
	} {
		changed := s
		mutate(&changed)
		if policy.Authorize(g, changed, s.IssuedAt) == nil {
			t.Fatal("changed intent acquired original verification authority")
		}
	}
	for _, mutate := range []func(*email.RegistrationVerificationSpec){
		func(s *email.RegistrationVerificationSpec) { s.Binding.UserID = identity.UserID(s.Payload.SubjectID) },
		func(s *email.RegistrationVerificationSpec) { s.Payload.CanonicalAddress = identifier.Canonical{} },
		func(s *email.RegistrationVerificationSpec) { s.IdentifierVersion = 0 },
		func(s *email.RegistrationVerificationSpec) { s.VerificationVersion = 0 },
		func(s *email.RegistrationVerificationSpec) { s.Payload.Version = 0 },
		func(s *email.RegistrationVerificationSpec) { s.IssuedAt = time.Time{} },
		func(s *email.RegistrationVerificationSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		func(s *email.RegistrationVerificationSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		func(s *email.RegistrationVerificationSpec) { s.ExpiresAt = s.IssuedAt },
	} {
		changed := s
		mutate(&changed)
		if output, err := policy.Payload(changed); err == nil || output.Subject != "" || output.Caveats != nil {
			t.Fatal("invalid registration input retained unsigned authority")
		}
	}
}

// Allowlist admission alone must not let a grant select another admitted callback.
func TestRegistrationVerificationBindsExactAllowedRedirect(t *testing.T) {
	c, original := registrationVerificationFixture(t)
	alternate := original
	alternate.Payload.Redirect.RawQuery = "state=alternate"
	c.Redirects = append(c.Redirects, alternate.Payload.Redirect.String())
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	first, err := policy.Payload(original)
	if err != nil {
		t.Fatal("original allowed callback was rejected", err)
	}
	second, err := policy.Payload(alternate)
	if err != nil {
		t.Fatal("alternate allowed callback was rejected", err)
	}
	firstGrant, secondGrant := registrationGrant(t, first), registrationGrant(t, second)
	if policy.Authorize(firstGrant, original, original.IssuedAt) != nil || policy.Authorize(secondGrant, alternate, alternate.IssuedAt) != nil {
		t.Fatal("independently issued callback authority was rejected")
	}
	if policy.Authorize(firstGrant, alternate, original.IssuedAt) == nil || policy.Authorize(secondGrant, original, original.IssuedAt) == nil {
		t.Fatal("grant substituted a different allowlisted callback")
	}
}

func TestRegistrationVerificationBoundsBeforeURLAllocation(t *testing.T) {
	c, original := registrationVerificationFixture(t)
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("a", 1<<20)
	for _, field := range []string{"issuer", "callback"} {
		t.Run(field, func(t *testing.T) {
			changed := c
			if field == "issuer" {
				changed.Issuer = "https://" + oversized
			} else {
				changed.Redirects = []string{"https://app.example.test/?" + oversized}
			}
			allocations := testing.AllocsPerRun(1, func() {
				policy, err := email.NewRegistrationVerificationPolicy(changed)
				if policy != nil || err != email.ErrInvalidVerification {
					t.Fatal("oversized startup URL admitted")
				}
			})
			if allocations != 0 {
				t.Fatalf("oversized startup URL allocated before admission: %g", allocations)
			}
		})
	}
	for _, field := range []string{"query", "path", "raw_path", "host", "fragment", "raw_fragment", "opaque", "scheme"} {
		t.Run(field, func(t *testing.T) {
			s := original
			switch field {
			case "query":
				s.Payload.Redirect.RawQuery = oversized
			case "path":
				s.Payload.Redirect.Path = oversized
			case "raw_path":
				s.Payload.Redirect.RawPath = oversized
			case "host":
				s.Payload.Redirect.Host = oversized
			case "fragment":
				s.Payload.Redirect.Fragment = oversized
			case "raw_fragment":
				s.Payload.Redirect.RawFragment = oversized
			case "opaque":
				s.Payload.Redirect.Opaque = oversized
			case "scheme":
				s.Payload.Redirect.Scheme = oversized
			}
			allocations := testing.AllocsPerRun(1, func() {
				payload, err := policy.Payload(s)
				if err != email.ErrInvalidVerification || payload.Caveats != nil {
					t.Fatal("oversized URL retained authority")
				}
			})
			if allocations != 0 {
				t.Fatalf("oversized URL allocated before admission: %g", allocations)
			}
		})
	}
}

func TestRegistrationVerificationAdmitsBoundedEncodedCallback(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	raw := "https://app.example.test/" + strings.Repeat("%61", 600)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.Redirects = []string{raw}
	s.Payload.Redirect = *u
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		t.Fatal("bounded encoded path was double-counted", err)
	}
	payload, err := policy.Payload(s)
	if err != nil || policy.Authorize(registrationGrant(t, payload), s, s.IssuedAt) != nil {
		t.Fatal("exact admitted encoded callback lost its authority", err)
	}
}

func FuzzRegistrationVerificationHostileIntent(f *testing.F) {
	for _, seed := range []string{"User+tag@xn--bcher-kva.example", "", "not-an-address", "a@example.test\x00", strings.Repeat("a", 4097)} {
		f.Add(seed, "https://app.example.test/verified?state=selected")
	}
	c, original := registrationVerificationFixture(f)
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw, redirect string) {
		// Bound fuzz input before constructing any URI/canonical projection.
		if len(raw) > 8192 || len(redirect) > 4096 {
			t.Skip()
		}
		s := original
		s.Payload.CanonicalAddress, _ = identifier.Normalize(identifier.Input(raw), c.Address.Canonicalization)
		u, err := url.Parse(redirect)
		if err != nil {
			return
		}
		s.Payload.Redirect = *u
		payload, err := policy.Payload(s)
		if err != nil {
			if payload.Subject != "" || payload.Caveats != nil {
				t.Fatal("hostile input retained partial authority")
			}
			return
		}
		if payload.ID != "" || payload.MaxUses != 1 || payload.Bearer || s.Payload.Redirect.String() != original.Payload.Redirect.String() {
			t.Fatal("hostile boundary widened verification authority")
		}
	})
}

func TestRegistrationVerificationRetainsOriginalBindingKeys(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	old, _ := email.NewRegistrationVerificationPolicy(c)
	p, _ := old.Payload(s)
	g := registrationGrant(t, p)
	c.CurrentBindingKeyVersion = 2
	c.RetainedBindingKeys[2] = [32]byte{51}
	next, _ := email.NewRegistrationVerificationPolicy(c)
	c.RetainedBindingKeys[1] = [32]byte{90}
	c.Redirects[0] = "https://unrelated.example.test"
	if next.Authorize(g, s, s.IssuedAt) != nil {
		t.Fatal("rotation/configuration mutation invalidated retained original key")
	}
	newPayload, err := next.Payload(s)
	if err != nil || newPayload.Caveats["email.binding_key_version"] != "2" || newPayload.Caveats["email.intent"] == p.Caveats["email.intent"] {
		t.Fatal("new issuance did not select its distinct current key")
	}
	delete(c.RetainedBindingKeys, 1)
	c.Redirects = []string{s.Payload.Redirect.String()}
	retired, retiredErr := email.NewRegistrationVerificationPolicy(c)
	if retiredErr != nil {
		t.Fatal(retiredErr)
	}
	if retired.Authorize(g, s, s.IssuedAt) == nil {
		t.Fatal("missing original key admitted a historical grant")
	}
}

func TestRegistrationVerificationConfigurationAndDiagnosticsDeny(t *testing.T) {
	c, s := registrationVerificationFixture(t)
	for _, mutate := range []func(*email.RegistrationVerificationConfig){
		func(c *email.RegistrationVerificationConfig) { c.Address = email.AddressPolicy{} },
		func(c *email.RegistrationVerificationConfig) { c.Issuer = "http://issuer.example.test" },
		func(c *email.RegistrationVerificationConfig) { c.Issuer += "#fragment" },
		func(c *email.RegistrationVerificationConfig) { c.Issuer += "?query=1" },
		func(c *email.RegistrationVerificationConfig) { c.Audience = "" },
		func(c *email.RegistrationVerificationConfig) { c.MaximumLifetime = 0 },
		func(c *email.RegistrationVerificationConfig) { c.MaximumLifetime = 24*time.Hour + time.Second },
		func(c *email.RegistrationVerificationConfig) { c.MaximumLifetime = time.Nanosecond },
		func(c *email.RegistrationVerificationConfig) { c.Redirects = nil },
		func(c *email.RegistrationVerificationConfig) {
			c.Redirects = []string{"http://app.example.test/verified"}
		},
		func(c *email.RegistrationVerificationConfig) {
			c.Redirects = []string{"https://user:secret@app.example.test/verified"}
		},
		func(c *email.RegistrationVerificationConfig) { c.Redirects = []string{c.Redirects[0], c.Redirects[0]} },
		func(c *email.RegistrationVerificationConfig) { c.CurrentBindingKeyVersion = 0 },
		func(c *email.RegistrationVerificationConfig) { c.RetainedBindingKeys = map[uint32][32]byte{1: {}} },
	} {
		changed := c
		mutate(&changed)
		if policy, err := email.NewRegistrationVerificationPolicy(changed); err == nil || policy != nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid startup policy admitted or disclosed input")
		}
	}
	policy, _ := email.NewRegistrationVerificationPolicy(c)
	for _, value := range []any{c, policy, s, s.Payload} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if rendered := fmt.Sprintf(format, value); strings.Contains(rendered, "bücher") || strings.Contains(rendered, "verified?") || strings.Contains(rendered, string(s.Binding.CommandID)) {
				t.Fatal("diagnostics disclosed private verification intent")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit JSON exported private verification intent")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil {
			t.Fatal("implicit text exported private verification intent")
		}
		if value.(interface{ LogValue() slog.Value }).LogValue().String() == "" {
			t.Fatal("structured redaction absent")
		}
	}
	var zero *email.RegistrationVerificationPolicy
	if _, err := zero.Payload(s); err == nil || zero.Authorize(capability.Grant{}, s, s.IssuedAt) == nil {
		t.Fatal("zero policy admitted authority")
	}
}
