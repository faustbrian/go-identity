package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestSelectedPasskeyOwnerRetainsCommonScopeAndDistinctCacheCustody(t *testing.T) {
	password := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	one := SingleFactorSessionAdmissionConfig{Verified: &password}
	_, legacy, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one})
	if err != nil {
		t.Fatal(err)
	}
	p := PasskeySessionAdmission{Profile: PasskeyAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", RPNamespace: "rp-a"}, Authority: &passkeyTestAuthority{}}
	methods, only, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{Passkey: &p})
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified || only == legacy {
		t.Fatal("passkey-only custody collapsed", err)
	}
	methods, both, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, Passkey: &p})
	if err != nil || len(methods) != 1 || both == only || both == legacy {
		t.Fatal("combined passkey custody collapsed", err)
	}
	for _, field := range []string{"deployment", "namespace", "audience", "RP", "authority", "typed-nil"} {
		foreign := p
		switch field {
		case "deployment":
			foreign.Profile.GlobalAuthorityID = "foreign"
		case "namespace":
			foreign.Profile.PolicyNamespace = "foreign"
		case "audience":
			foreign.Profile.Audience = "foreign"
		case "RP":
			foreign.Profile.RPNamespace = ""
		case "authority":
			foreign.Authority = nil
		case "typed-nil":
			foreign.Authority = (*passkeyTestAuthority)(nil)
		}
		if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, Passkey: &foreign}); err == nil {
			t.Fatal("foreign or missing passkey owner admitted", field)
		}
	}
	other := p
	other.Profile.RPNamespace = "rp-b"
	if _, different, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, Passkey: &other}); err != nil || different == both {
		t.Fatal("RP selection not bound to cache custody", err)
	}
}

func TestSelectedPasswordMFARetainsDistinctCacheCustodyAndOwnerProfile(t *testing.T) {
	password := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	one := SingleFactorSessionAdmissionConfig{Verified: &password}
	_, legacy, err := singleFactorAdmission(one)
	if err != nil {
		t.Fatal(err)
	}
	methods, only, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{MFAPassword: &password})
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified || only == legacy {
		t.Fatal("password MFA-only selection collapsed", err)
	}
	methods, both, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, MFAPassword: &password})
	if err != nil || len(methods) != 1 || both == only || both == legacy {
		t.Fatal("combined password profile collapsed", err)
	}
	foreign := password
	foreign.PolicyNamespace = "different"
	if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, MFAPassword: &foreign}); err == nil {
		t.Fatal("foreign password authority selected")
	}
	foreign = password
	foreign.AuthenticationMethod = "email-otp"
	if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{MFAPassword: &foreign}); err == nil {
		t.Fatal("non-password primary selected")
	}
}

func TestSelectedSessionAdmissionSeparatesMFAFromSingleFactor(t *testing.T) {
	p := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	one := SingleFactorSessionAdmissionConfig{MagicLink: &p}
	_, legacy, err := singleFactorAdmission(one)
	if err != nil {
		t.Fatal(err)
	}
	methods, same, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one})
	if err != nil || same != legacy || len(methods) != 1 {
		t.Fatal("legacy selection changed", err)
	}
	methods, combined, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, MFAMagicLink: &p})
	if err != nil || combined == legacy || len(methods) != 1 || methods[0] != session.AuthenticationMagicLink {
		t.Fatal("MFA selection not bound distinctly", err)
	}
	methods, only, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{MFAMagicLink: &p})
	if err != nil || only == combined || only == legacy || len(methods) != 1 {
		t.Fatal("MFA-only selection collapsed", err)
	}
	for _, field := range []string{"deployment", "namespace", "audience"} {
		foreign := p
		switch field {
		case "deployment":
			foreign.GlobalAuthorityID = "foreign"
		case "namespace":
			foreign.PolicyNamespace = "foreign"
		case "audience":
			foreign.Audience = "foreign"
		}
		if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{SingleFactor: one, MFAMagicLink: &foreign}); err == nil {
			t.Fatal("foreign MFA owner admitted", field)
		}
	}
	if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{}); err == nil {
		t.Fatal("empty selection admitted")
	}
}
