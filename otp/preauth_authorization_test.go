package otp_test

import (
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func boundPreAuthSpec(t *testing.T) session.PreAuthTransactionSpec {
	t.Helper()
	now := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	return session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: preAuthID(), Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.otp.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/return", Nonce: [32]byte{1}, Remember: rememberPolicy(t), PolicyID: "login", PolicyVersion: 11}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, Version: 1}
}

func TestBoundPreAuthContinuationBindsEveryOriginalField(t *testing.T) {
	s := digestScopeSpec(t)
	s.AuthorizationBinding = [32]byte{}
	base := boundPreAuthSpec(t)
	bind := func(p session.PreAuthTransactionSpec) [32]byte {
		record, err := session.NewPreAuthTransaction(p)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := otp.NewBoundPreAuthAuthorization(record)
		if err != nil {
			t.Fatal(err)
		}
		if retained, ok := flow.PreAuthTransaction(); !ok || retained != record {
			t.Fatal("full original flow custody lost")
		}
		c, err := otp.NewContinuation(s, flow, p.Binding.Intent.Remember)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bindings()
		return b.Scope.AuthorizationBinding
	}
	want := bind(base)
	for _, change := range []func(*session.PreAuthTransactionSpec){
		func(p *session.PreAuthTransactionSpec) { p.Binding.ID = "AgICAgICAgICAgICAgICAg" },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.Action = "identity.otp.mfa" },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.Origin = "https://other.test" },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.CallbackURL = "" },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.Nonce[1] = 1 },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.PolicyID = "other" },
		func(p *session.PreAuthTransactionSpec) { p.Binding.Intent.PolicyVersion++ },
		func(p *session.PreAuthTransactionSpec) { p.Binding.IssuedAt = p.Binding.IssuedAt.Add(time.Nanosecond) },
		func(p *session.PreAuthTransactionSpec) {
			p.Binding.ExpiresAt = p.Binding.ExpiresAt.Add(time.Nanosecond)
		},
		func(p *session.PreAuthTransactionSpec) { p.Cookie.KeyVersion++ },
		func(p *session.PreAuthTransactionSpec) { p.Cookie.Sum[1] = 1 },
		func(p *session.PreAuthTransactionSpec) { p.Version++ },
	} {
		copy := base
		change(&copy)
		if got := bind(copy); got == want {
			t.Fatal("different original flow shared authorization binding")
		}
	}
	legacy, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: base.Binding.ID})
	if _, ok := legacy.PreAuthTransaction(); ok {
		t.Fatal("legacy ID fabricated complete flow")
	}
	c, err := otp.NewContinuation(s, legacy, base.Binding.Intent.Remember)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bindings()
	if b.Scope.AuthorizationBinding == want {
		t.Fatal("legacy ID-only context borrowed bound-flow profile")
	}
}

func TestBoundPreAuthContinuationRejectsSubstitution(t *testing.T) {
	if _, err := otp.NewBoundPreAuthAuthorization(session.PreAuthTransaction{}); err == nil {
		t.Fatal("zero original flow admitted")
	}
	p := boundPreAuthSpec(t)
	record, _ := session.NewPreAuthTransaction(p)
	flow, _ := otp.NewBoundPreAuthAuthorization(record)
	s := digestScopeSpec(t)
	s.AuthorizationBinding = [32]byte{}
	s.TenantID = "foreign"
	if _, err := otp.NewContinuation(s, flow, p.Binding.Intent.Remember); err == nil {
		t.Fatal("cross-tenant original flow admitted")
	}
	s.TenantID = "tenant"
	rememberSpec, _ := p.Binding.Intent.Remember.Bindings()
	rememberSpec.Choice = session.PersistentSession
	changed, _ := session.NewRememberPolicy(rememberSpec)
	if _, err := otp.NewContinuation(s, flow, changed); err == nil {
		t.Fatal("original remember choice changed")
	}
}
