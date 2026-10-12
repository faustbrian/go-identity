package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSingleFactorSelectionRequiresExactSharedOwners(t *testing.T) {
	verified := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	otp := OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	magic := MagicLinkAdmissionConfig(otp)
	selection := SingleFactorSessionAdmissionConfig{Verified: &verified, OTP: &otp, MagicLink: &magic}
	methods, profile, err := singleFactorAdmission(selection)
	if err != nil || len(methods) != 3 || profile == "" {
		t.Fatal("valid shared owners", err)
	}
	for _, mutate := range []func(*SingleFactorSessionAdmissionConfig){
		func(s *SingleFactorSessionAdmissionConfig) { *s = SingleFactorSessionAdmissionConfig{} },
		func(s *SingleFactorSessionAdmissionConfig) {
			p := *s.MagicLink
			p.Audience = "foreign"
			s.MagicLink = &p
		},
		func(s *SingleFactorSessionAdmissionConfig) { p := *s.OTP; p.PolicyNamespace = "foreign"; s.OTP = &p },
		func(s *SingleFactorSessionAdmissionConfig) {
			p := *s.Verified
			p.GlobalAuthorityID = "foreign"
			s.Verified = &p
		},
		func(s *SingleFactorSessionAdmissionConfig) {
			p := *s.MagicLink
			p.GlobalAuthorityID = ""
			s.MagicLink = &p
		},
	} {
		bad := selection
		mutate(&bad)
		if _, _, err := singleFactorAdmission(bad); err == nil {
			t.Fatal("invalid owner selection")
		}
	}
	if owner, err := NewSingleFactorSessionService(nil, SingleFactorSessionServiceConfig{Admission: selection}); owner != nil || err == nil {
		t.Fatal("absent primary/validation", err)
	}
	selected, reduced, err := singleFactorAdmission(SingleFactorSessionAdmissionConfig{MagicLink: &magic})
	if err != nil || len(selected) != 1 || selected[0] != session.AuthenticationMagicLink || reduced == profile {
		t.Fatal("selected method not bound into owner profile", err)
	}
}
