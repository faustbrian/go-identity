package password_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

func resetProfileFixture(t *testing.T) (password.ResetProfileConfig, password.ResetGrantSpec) {
	t.Helper()
	issued := time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "password-reset", MaximumLifetime: 30 * time.Minute, Callbacks: []string{"https://identity.test/reset/confirmed"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {97}}}, password.ResetGrantSpec{TenantID: "tenant", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CredentialID: "password-credential", CredentialVersion: math.MaxUint64, CredentialAuthorityVersion: 5, UserAuthorityVersion: 6, IdentifierID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", IdentifierVersion: 7, OriginCommandID: command, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset/confirmed", IssuedAt: issued, ExpiresAt: issued.Add(30 * time.Minute)}
}

func signResetGrant(t *testing.T, payload capability.Payload, now time.Time) capability.Grant {
	t.Helper()
	key := bytes.Repeat([]byte{98}, 32)
	signer, err := capability.NewHMACSHA256Signer("reset-fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: payload.Issuer, ID: "reset-fixture", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := capability.NewService(capability.ServiceConfig{Issuer: payload.Issuer, Signer: signer, Resolver: resolver, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	// The durable issuer, not ResetProfile, selects the actual random grant ID.
	payload.ID = "synthetic-reset-grant"
	proof, _, err := service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal("signed reset fixture", err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	grant, err := service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), payload.Audiences[0])
	if err != nil {
		t.Fatal("actual capability verification", err)
	}
	return grant
}

func TestResetProfileSignedClosedOriginalScope(t *testing.T) {
	c, s := resetProfileFixture(t)
	p, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := p.Payload(s)
	if err != nil || payload.ID != "" || payload.MaxUses != 1 || payload.Bearer || payload.Subject != string(s.UserID) || payload.Operation != "identity.password.reset-complete" || payload.Caveats["password.recovery-path"] != "emailed_password_reset" || payload.Caveats["password.credential-version"] != "18446744073709551615" || strings.Contains(payload.Caveats["password.callback"], "identity.test") {
		t.Fatal("reset payload lost original closed scope", err)
	}
	grant := signResetGrant(t, payload, s.IssuedAt.Add(time.Second))
	if err := p.Authorize(grant, s, s.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal("genuine original reset rejected", err)
	}
	for name, change := range map[string]func(*password.ResetGrantSpec){
		"tenant":               func(s *password.ResetGrantSpec) { s.TenantID = "foreign" },
		"user":                 func(s *password.ResetGrantSpec) { s.UserID = "other-user" },
		"credential":           func(s *password.ResetGrantSpec) { s.CredentialID = "other-credential" },
		"password-version":     func(s *password.ResetGrantSpec) { s.CredentialVersion-- },
		"credential-authority": func(s *password.ResetGrantSpec) { s.CredentialAuthorityVersion++ },
		"user-authority":       func(s *password.ResetGrantSpec) { s.UserAuthorityVersion++ },
		"identifier":           func(s *password.ResetGrantSpec) { s.IdentifierID = "other-identifier" },
		"identifier-version":   func(s *password.ResetGrantSpec) { s.IdentifierVersion++ },
		"origin":               func(s *password.ResetGrantSpec) { s.OriginCommandID, _ = identity.NewCommandID() },
		"path":                 func(s *password.ResetGrantSpec) { s.RecoveryPath = auth.RecoveryPathPhone },
		"callback":             func(s *password.ResetGrantSpec) { s.CallbackURL += "?changed=1" },
		"renewed-issuance":     func(s *password.ResetGrantSpec) { s.IssuedAt = s.IssuedAt.Add(time.Second) },
		"renewed-expiry":       func(s *password.ResetGrantSpec) { s.ExpiresAt = s.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			change(&changed)
			if !errors.Is(p.Authorize(grant, changed, s.IssuedAt.Add(time.Second)), password.ErrInvalidReset) {
				t.Fatal("reset scope substitution admitted")
			}
		})
	}
	for _, now := range []time.Time{{}, s.IssuedAt.Add(-time.Nanosecond), s.ExpiresAt, s.ExpiresAt.Add(time.Second)} {
		if !errors.Is(p.Authorize(grant, s, now), password.ErrInvalidReset) {
			t.Fatal("reset lifetime renewed or ignored")
		}
	}
	if !errors.Is(p.Authorize(capability.Grant{}, s, s.IssuedAt), password.ErrInvalidReset) {
		t.Fatal("unsigned authority admitted")
	}
	for name, change := range map[string]func(*capability.Payload){
		"purpose":        func(p *capability.Payload) { p.Operation = "identity.email.verification-confirm" },
		"extra-audience": func(p *capability.Payload) { p.Audiences = append(p.Audiences, "foreign") },
		"reusable":       func(p *capability.Payload) { p.MaxUses = 0 },
		"extra-caveat":   func(p *capability.Payload) { p.Caveats["extra"] = "invented" },
		"activation":     func(p *capability.Payload) { p.NotBefore = p.NotBefore.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			wire, _ := p.Payload(s)
			change(&wire)
			g := signResetGrant(t, wire, s.IssuedAt.Add(time.Second))
			if !errors.Is(p.Authorize(g, s, s.IssuedAt.Add(time.Second)), password.ErrInvalidReset) {
				t.Fatal("signed incompatible reset profile admitted")
			}
		})
	}
}

func TestResetProfileRetainedKeysFrozenAndRedacted(t *testing.T) {
	c, s := resetProfileFixture(t)
	p, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.Payload(s)
	g := signResetGrant(t, wire, s.IssuedAt)
	c.Callbacks[0] = "https://foreign.test"
	c.RetainedBindingKeys[1] = [32]byte{99}
	if err := p.Authorize(g, s, s.IssuedAt); err != nil {
		t.Fatal("caller changed frozen reset profile", err)
	}
	rotated, _ := resetProfileFixture(t)
	rotated.CurrentBindingKeyVersion = 2
	rotated.RetainedBindingKeys[2] = [32]byte{100}
	next, err := password.NewResetProfile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Authorize(g, s, s.IssuedAt.Add(time.Minute)); err != nil {
		t.Fatal("retained original reset key lost", err)
	}
	newWire, _ := next.Payload(s)
	if newWire.Caveats["password.binding-key-version"] != "2" || newWire.IssuedAt != wire.IssuedAt || newWire.ExpiresAt != wire.ExpiresAt {
		t.Fatal("rotation renewed original timestamps or used old key")
	}
	delete(rotated.RetainedBindingKeys, 1)
	retired, err := password.NewResetProfile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(retired.Authorize(g, s, s.IssuedAt), password.ErrInvalidReset) {
		t.Fatal("retired reset key admitted")
	}
	for _, v := range []any{c, s, p} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			got := fmt.Sprintf(verb, v)
			if strings.Contains(got, string(s.UserID)) || strings.Contains(got, s.CallbackURL) || strings.Contains(got, "foreign.test") {
				t.Fatal("implicit reset diagnostics disclosed intent")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("implicit reset JSON exported")
		}
	}
}

func TestResetProfileInvalidConfigurationAndSpecs(t *testing.T) {
	for name, change := range map[string]func(*password.ResetProfileConfig){
		"issuer":                  func(c *password.ResetProfileConfig) { c.Issuer = "http://identity.test" },
		"issuer-query":            func(c *password.ResetProfileConfig) { c.Issuer += "?query=1" },
		"issuer-empty-fragment":   func(c *password.ResetProfileConfig) { c.Issuer += "#" },
		"audience":                func(c *password.ResetProfileConfig) { c.Audience = "" },
		"lifetime":                func(c *password.ResetProfileConfig) { c.MaximumLifetime = time.Hour + time.Second },
		"fraction":                func(c *password.ResetProfileConfig) { c.MaximumLifetime = time.Second + 1 },
		"callbacks":               func(c *password.ResetProfileConfig) { c.Callbacks = nil },
		"duplicate-callback":      func(c *password.ResetProfileConfig) { c.Callbacks = append(c.Callbacks, c.Callbacks[0]) },
		"callback-fragment":       func(c *password.ResetProfileConfig) { c.Callbacks[0] += "#fragment" },
		"callback-empty-fragment": func(c *password.ResetProfileConfig) { c.Callbacks[0] += "#" },
		"oversized-callback": func(c *password.ResetProfileConfig) {
			c.Callbacks[0] = "https://identity.test/" + strings.Repeat("x", 2048)
		},
		"key":     func(c *password.ResetProfileConfig) { c.RetainedBindingKeys[1] = [32]byte{} },
		"version": func(c *password.ResetProfileConfig) { c.CurrentBindingKeyVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := resetProfileFixture(t)
			change(&c)
			p, err := password.NewResetProfile(c)
			if !errors.Is(err, password.ErrInvalidReset) || p != (password.ResetProfile{}) {
				t.Fatal("invalid reset startup admitted")
			}
		})
	}
	c, s := resetProfileFixture(t)
	p, _ := password.NewResetProfile(c)
	for name, change := range map[string]func(*password.ResetGrantSpec){
		"credential-version-zero": func(s *password.ResetGrantSpec) { s.CredentialVersion = 0 },
		"identifier-version-zero": func(s *password.ResetGrantSpec) { s.IdentifierVersion = 0 },
		"authority-zero":          func(s *password.ResetGrantSpec) { s.UserAuthorityVersion = 0 },
		"control-id":              func(s *password.ResetGrantSpec) { s.CredentialID = "private\ncredential" },
		"oversized-id":            func(s *password.ResetGrantSpec) { s.UserID = identity.UserID(strings.Repeat("u", 129)) },
		"fractional-issuance":     func(s *password.ResetGrantSpec) { s.IssuedAt = s.IssuedAt.Add(1) },
		"non-UTC":                 func(s *password.ResetGrantSpec) { s.ExpiresAt = s.ExpiresAt.In(time.FixedZone("display", 3600)) },
		"expiry":                  func(s *password.ResetGrantSpec) { s.ExpiresAt = s.IssuedAt },
		"excess-lifetime":         func(s *password.ResetGrantSpec) { s.ExpiresAt = s.IssuedAt.Add(time.Hour) },
		"missing-path":            func(s *password.ResetGrantSpec) { s.RecoveryPath = auth.RecoveryPathUnspecified },
		"origin":                  func(s *password.ResetGrantSpec) { s.OriginCommandID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			change(&changed)
			wire, err := p.Payload(changed)
			if !errors.Is(err, password.ErrInvalidReset) || wire.Version != 0 {
				t.Fatal("invalid reset intent admitted")
			}
		})
	}
	if _, err := (password.ResetProfile{}).Payload(s); !errors.Is(err, password.ErrInvalidReset) {
		t.Fatal("zero reset profile admitted")
	}
}
