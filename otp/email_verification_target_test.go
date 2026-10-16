package otp_test

import (
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestEmailVerificationTargetPreservesCanonicalSelectorAndVersions(t *testing.T) {
	spec := otp.EmailVerificationTargetSpec{IdentifierID: "pending:email", IdentifierVersion: 2, VerificationVersion: 2, FactorVersion: 7}
	target, err := otp.NewEmailVerificationTarget(spec)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := target.ScopeTarget()
	if err != nil || !strings.HasPrefix(raw, "email_verification_otp:") || len(raw) > 256 {
		t.Fatal("canonical recovery selector missing", err)
	}
	parsed, err := otp.ParseEmailVerificationTarget(raw)
	got, readErr := parsed.Bindings()
	if err != nil || readErr != nil || got != spec {
		t.Fatal("original pending target changed", err, readErr)
	}
	if !strings.Contains(fmt.Sprintf("%#v", target), "redacted") {
		t.Fatal("target diagnostic disclosed private intent")
	}
	for _, bad := range []string{"", strings.Repeat("x", 257), raw + ":extra", strings.Replace(raw, "email_verification_otp", "emailed_password_reset", 1), strings.Replace(raw, ":13:", ":013:", 1), strings.Replace(raw, ":2:2:", ":02:2:", 1), strings.Replace(raw, ":2:2:", ":2:3:", 1), strings.TrimSuffix(raw, ":7") + ":0"} {
		if _, err := otp.ParseEmailVerificationTarget(bad); err == nil {
			t.Fatal("noncanonical or substituted target admitted")
		}
	}
	for _, mutate := range []func(*otp.EmailVerificationTargetSpec){
		func(s *otp.EmailVerificationTargetSpec) { s.IdentifierID = "" },
		func(s *otp.EmailVerificationTargetSpec) {
			s.IdentifierID = identity.IdentifierID(strings.Repeat("x", 129))
		},
		func(s *otp.EmailVerificationTargetSpec) { s.IdentifierVersion = 0 },
		func(s *otp.EmailVerificationTargetSpec) { s.VerificationVersion++ },
		func(s *otp.EmailVerificationTargetSpec) { s.FactorVersion = ^uint64(0) },
	} {
		changed := spec
		mutate(&changed)
		if _, err := otp.NewEmailVerificationTarget(changed); err == nil {
			t.Fatal("invalid original target admitted")
		}
	}
	if _, err := (otp.EmailVerificationTarget{}).ScopeTarget(); err == nil {
		t.Fatal("zero target exposed scope")
	}
}

func FuzzEmailVerificationTarget(f *testing.F) {
	for _, seed := range []string{"", "email_verification_otp:13:pending:email:2:2:7", "email_verification_otp:1:x:1:1:1", "email_verification_otp:999999999999999999999:x:1:1:1", "email_verification_otp:1:x:18446744073709551615:18446744073709551615:1", "email_verification_otp:1:x:01:1:1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, err := otp.ParseEmailVerificationTarget(raw)
		if err != nil {
			return
		}
		got, err := target.ScopeTarget()
		if err != nil || got != raw || len(got) > 256 {
			t.Fatal("accepted target was not bounded and canonical")
		}
		bindings, err := target.Bindings()
		if err != nil {
			t.Fatal("accepted target lost bindings")
		}
		rebuilt, err := otp.NewEmailVerificationTarget(bindings)
		if err != nil {
			t.Fatal("accepted target could not be rebuilt")
		}
		again, _ := rebuilt.ScopeTarget()
		if again != raw {
			t.Fatal("accepted target changed identity on reconstruction")
		}
	})
}
