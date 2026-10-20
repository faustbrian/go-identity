package session

import (
	"context"
	"errors"
	"testing"
)

func TestPhoneRecoveryPreAuthCarriesNoSessionChoice(t *testing.T) {
	token, key, original := preAuthFixture(t)
	s := original
	s.Binding.Intent.Action = "identity.phone.password-reset-request"
	s.Binding.Intent.Purpose = PreAuthPhonePasswordRecovery
	s.Binding.Intent.Remember = RememberPolicy{}
	s.Binding.Intent.IdentifierBinding = [32]byte{7}
	var err error
	s.Cookie, err = token.PreAuthDigest(key, s.Binding)
	if err != nil {
		t.Fatal("sessionless recovery commitment unavailable", err)
	}
	record, err := NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Check(s.Binding.IssuedAt, s.Binding, s.Cookie); err != nil {
		t.Fatal(err)
	}
	got, err := record.Bindings()
	if err != nil || got != s || got.Binding.Intent.Remember != (RememberPolicy{}) {
		t.Fatal("recovery invented a session policy", err)
	}
	for name, mutate := range map[string]func(*PreAuthTransactionSpec){
		"login purpose":   func(s *PreAuthTransactionSpec) { s.Binding.Intent.Purpose = PreAuthSessionIssuance },
		"unknown purpose": func(s *PreAuthTransactionSpec) { s.Binding.Intent.Purpose = 255 },
		"login action":    func(s *PreAuthTransactionSpec) { s.Binding.Intent.Action = "identity.password.signin" },
		"session choice":  func(s *PreAuthTransactionSpec) { s.Binding.Intent.Remember = original.Binding.Intent.Remember },
		"unbound number":  func(s *PreAuthTransactionSpec) { s.Binding.Intent.IdentifierBinding = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if _, err := NewPreAuthTransaction(changed); err == nil {
				t.Fatal("foreign/ambiguous recovery purpose admitted")
			}
			if _, err := token.PreAuthDigest(key, changed.Binding); err == nil {
				t.Fatal("foreign recovery cookie derived")
			}
		})
	}
	if !errors.Is(record.Check(s.Binding.ExpiresAt, s.Binding, s.Cookie), ErrPreAuthDenied) {
		t.Fatal("recovery pre-auth expiry renewed")
	}
}

func TestPhoneRecoveryIssuerRejectsRememberAndLoginSubstitution(t *testing.T) {
	legacy, _, executor, clock := preAuthIssuerFixture(t)
	c := legacy.config
	c.Action = "identity.phone.password-reset-request"
	c.Purpose = PreAuthPhonePasswordRecovery
	issuer, err := NewPreAuthIssuer(executor, c)
	if err != nil {
		t.Fatal("sessionless recovery issuer unavailable", err)
	}
	input := PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: "tenant", CorrelationID: "recovery", IdentifierBinding: [32]byte{1}}
	prepared, err := issuer.Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	command, ok := prepared.Command()
	if !ok {
		t.Fatal("missing original recovery command")
	}
	spec, err := command.Record.Bindings()
	if err != nil || spec.Binding.Intent.Purpose != PreAuthPhonePasswordRecovery || spec.Binding.Intent.Remember != (RememberPolicy{}) || !spec.Binding.IssuedAt.Equal(clock.now) {
		t.Fatal("issuer substituted session lifetime", err)
	}
	if legacy.originalProfile(command) || !issuer.originalProfile(command) {
		t.Fatal("issuer profiles cross-admitted")
	}
	_, _, login := preAuthFixture(t)
	input.Remember = login.Binding.Intent.Remember
	if _, err := issuer.Prepare(input); err == nil {
		t.Fatal("remember accepted on non-issuing recovery")
	}
	executor.execute = func(context.Context, PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		return preAuthCommitted(command), nil
	}
	issued, err := issuer.Issue(context.Background(), prepared)
	if err != nil || issued.Flow.state == nil || issued.Cookie.Name != "__Host-identity_flow" {
		t.Fatal("committed original recovery cookie not delivered", err)
	}
	if _, err := issued.Token.Reveal(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PreAuthIssuerConfig){
		func(c *PreAuthIssuerConfig) { c.Purpose = PreAuthSessionIssuance },
		func(c *PreAuthIssuerConfig) { c.Action = "identity.password.signin" },
		func(c *PreAuthIssuerConfig) { c.Purpose = 255 },
	} {
		invalid := c
		change(&invalid)
		if _, err := NewPreAuthIssuer(executor, invalid); err == nil {
			t.Fatal("invalid recovery issuer configuration admitted")
		}
	}
}
