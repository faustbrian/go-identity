package password_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-identity/password"
)

func TestResetProfileResolveOriginal(t *testing.T) {
	c, original := resetProfileFixture(t)
	p, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	now := original.IssuedAt.Add(time.Second)
	grant := signResetGrant(t, wire, now)
	c.CurrentBindingKeyVersion = 2
	c.RetainedBindingKeys[2] = [32]byte{99}
	c.Callbacks = append(c.Callbacks, "https://identity.test/another-reset")
	rotated, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.ResolveOriginal(grant, now)
	if err != nil || got != original {
		t.Fatal("original reset scope was changed or lost", err)
	}
	for _, at := range []time.Time{{}, original.IssuedAt.Add(-time.Nanosecond), original.ExpiresAt} {
		got, err := rotated.ResolveOriginal(grant, at)
		if !errors.Is(err, password.ErrInvalidReset) || got != (password.ResetGrantSpec{}) {
			t.Fatal("invalid lifetime returned authority")
		}
	}
	for name, change := range map[string]func(*password.ResetProfileConfig){
		"retired-key":      func(c *password.ResetProfileConfig) { delete(c.RetainedBindingKeys, 1) },
		"retired-callback": func(c *password.ResetProfileConfig) { c.Callbacks = []string{"https://identity.test/different"} },
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := resetProfileFixture(t)
			config.CurrentBindingKeyVersion = 2
			config.RetainedBindingKeys[2] = [32]byte{99}
			change(&config)
			profile, err := password.NewResetProfile(config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := profile.ResolveOriginal(grant, now)
			if !errors.Is(err, password.ErrInvalidReset) || got != (password.ResetGrantSpec{}) {
				t.Fatal("retired scope returned authority")
			}
		})
	}
	for _, profile := range []password.ResetProfile{p, {}} {
		got, err := profile.ResolveOriginal(capability.Grant{}, now)
		if !errors.Is(err, password.ErrInvalidReset) || got != (password.ResetGrantSpec{}) {
			t.Fatal("zero grant returned authority")
		}
	}
}

func TestResetProfileResolveOriginalRejectsSignedMalformedScope(t *testing.T) {
	c, original := resetProfileFixture(t)
	p, _ := password.NewResetProfile(c)
	now := original.IssuedAt.Add(time.Second)
	changes := map[string]func(*capability.Payload){
		"extra-caveat":     func(w *capability.Payload) { w.Caveats["extra"] = "foreign" },
		"missing-version":  func(w *capability.Payload) { delete(w.Caveats, "password.user-authority-version") },
		"foreign-resource": func(w *capability.Payload) { w.Resource = "foreign/password-credential" },
		"empty-credential": func(w *capability.Payload) { w.Resource = "identity.password/" },
		"foreign-path":     func(w *capability.Payload) { w.Caveats["password.recovery-path"] = "phone" },
		"foreign-callback": func(w *capability.Payload) { w.Caveats["password.callback"] = "foreign" },
		"extra-audience":   func(w *capability.Payload) { w.Audiences = append(w.Audiences, "foreign") },
		"invalid-origin":   func(w *capability.Payload) { w.CorrelationID = "invalid" },
	}
	for _, field := range []string{"password.credential-version", "password.credential-authority-version", "password.user-authority-version", "password.identifier-version", "password.binding-key-version"} {
		for _, value := range []string{"0", "01", "-1", "18446744073709551616"} {
			changes[field+"/"+value] = func(w *capability.Payload) { w.Caveats[field] = value }
		}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			wire, _ := p.Payload(original)
			change(&wire)
			grant := signResetGrant(t, wire, now)
			got, err := p.ResolveOriginal(grant, now)
			if !errors.Is(err, password.ErrInvalidReset) || got != (password.ResetGrantSpec{}) {
				t.Fatal("signed malformed reset scope returned authority")
			}
		})
	}
}
