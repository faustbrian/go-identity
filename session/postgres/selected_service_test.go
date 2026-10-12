package postgres

import (
	"testing"

	"github.com/faustbrian/go-identity/session"
)

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
