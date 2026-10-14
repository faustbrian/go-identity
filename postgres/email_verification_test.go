package postgres

import (
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestEmailVerificationFields(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent := EmailVerificationIntent{Change: identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "identifier", Action: identity.IdentifierVerify, ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}, CanonicalAddress: "synthetic@example.test", ComparisonProfile: "email-v1", RegistrationCommandID: id}
	fields, err := EmailVerificationFields(intent)
	if err != nil || len(fields) != 10 {
		t.Fatal("valid original signup intent rejected", err)
	}
	seen := map[string]bool{}
	for _, field := range fields {
		if seen[field.Name] || !strings.HasPrefix(field.Name, "email-verification.") {
			t.Fatal("duplicate or foreign owned field")
		}
		seen[field.Name] = true
	}
	for _, mutate := range []func(*EmailVerificationIntent){
		func(p *EmailVerificationIntent) { p.Change.TenantID = "" },
		func(p *EmailVerificationIntent) { p.Change.UserID = "" },
		func(p *EmailVerificationIntent) { p.Change.ID = "" },
		func(p *EmailVerificationIntent) { p.Change.ExpectedUserVersion = 0 },
		func(p *EmailVerificationIntent) { p.Change.ExpectedUserVersion = ^uint64(0) },
		func(p *EmailVerificationIntent) { p.Change.ExpectedAuthorityVersion = 0 },
		func(p *EmailVerificationIntent) { p.Change.ExpectedAuthorityVersion = ^uint64(0) },
		func(p *EmailVerificationIntent) { p.Change.ExpectedIdentifierVersion = 2 },
		func(p *EmailVerificationIntent) { p.Change.ExpectedVerificationVersion = 2 },
		func(p *EmailVerificationIntent) { p.Change.Kind = identity.IdentifierEmail },
		func(p *EmailVerificationIntent) { p.Change.CanonicalValue = p.CanonicalAddress },
		func(p *EmailVerificationIntent) { p.Change.DisplayValue = "replacement" },
		func(p *EmailVerificationIntent) { p.CanonicalAddress = "" },
		func(p *EmailVerificationIntent) { p.ComparisonProfile = "" },
		func(p *EmailVerificationIntent) { p.RegistrationCommandID = "invalid" },
	} {
		changed := intent
		mutate(&changed)
		if _, err := EmailVerificationFields(changed); err == nil {
			t.Fatal("invalid original signup intent accepted")
		}
	}
	if diagnostic := fmt.Sprintf("%+v", intent); strings.Contains(diagnostic, intent.CanonicalAddress) || strings.Contains(diagnostic, string(intent.RegistrationCommandID)) {
		t.Fatal("original account metadata disclosed")
	}
	if _, err := intent.MarshalJSON(); err == nil {
		t.Fatal("original intent serialized")
	}
}
