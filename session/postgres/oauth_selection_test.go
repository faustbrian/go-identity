package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOAuthSelectionSharesVerifiedKindWithoutLosingOwnerCustody(t *testing.T) {
	password := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	oauth := password
	oauth.AuthenticationMethod, oauth.CredentialKind, oauth.CredentialOwner = "oauth", identity.CredentialProvider, "identity/oauth"
	_, passwordOnly, err := singleFactorAdmission(SingleFactorSessionAdmissionConfig{Verified: &password})
	if err != nil {
		t.Fatal(err)
	}
	_, oauthOnly, err := singleFactorAdmission(SingleFactorSessionAdmissionConfig{OAuth: &oauth})
	if err != nil {
		t.Fatal(err)
	}
	selection := SingleFactorSessionAdmissionConfig{Verified: &password, OAuth: &oauth}
	methods, both, err := singleFactorAdmission(selection)
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified || both == passwordOnly || both == oauthOnly {
		t.Fatal("combined selection must retain both owners under one authentication kind", err)
	}
	for name, change := range map[string]func(*IdentifierAdmissionConfig){
		"deployment": func(p *IdentifierAdmissionConfig) { p.GlobalAuthorityID = "foreign" },
		"namespace":  func(p *IdentifierAdmissionConfig) { p.PolicyNamespace = "foreign" },
		"audience":   func(p *IdentifierAdmissionConfig) { p.Audience = "foreign" },
		"method":     func(p *IdentifierAdmissionConfig) { p.AuthenticationMethod = "password" },
		"kind":       func(p *IdentifierAdmissionConfig) { p.CredentialKind = identity.CredentialPassword },
		"owner":      func(p *IdentifierAdmissionConfig) { p.CredentialOwner = "identity/password" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := oauth
			change(&changed)
			if _, _, err := singleFactorAdmission(SingleFactorSessionAdmissionConfig{Verified: &password, OAuth: &changed}); err == nil {
				t.Fatal("foreign or mismatched OAuth owner admitted")
			}
		})
	}
	if _, _, err := singleFactorAdmission(SingleFactorSessionAdmissionConfig{Verified: &oauth, OAuth: &oauth}); err == nil {
		t.Fatal("ambiguous duplicate OAuth selection admitted")
	}
	for name, selected := range map[string]SelectedSessionAdmissionConfig{
		"password MFA":            {SingleFactor: selection, MFAPassword: &password},
		"OAuth with password MFA": {SingleFactor: SingleFactorSessionAdmissionConfig{OAuth: &oauth}, MFAPassword: &password},
		"magic-link MFA":          {SingleFactor: selection, MFAMagicLink: &MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}},
		"passkey":                 {SingleFactor: selection, Passkey: &PasskeySessionAdmission{Profile: PasskeyAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", RPNamespace: "rp"}, Authority: &passkeyTestAuthority{}}},
	} {
		t.Run(name, func(t *testing.T) {
			methods, profile, err := selectedSessionAdmission(selected)
			if err != nil || profile == both || len(methods) == 0 {
				t.Fatal("additional owner lost OAuth selection or cache custody", err)
			}
		})
	}
}

func TestOAuthRevocationSelectsOriginalMethodAndFreezesBothProfiles(t *testing.T) {
	oauth, providerSession, account := oauthSigninEffectFixture(t)
	passwordSession, command, password := identifierSessionFixture(t)
	selection := SingleFactorSessionAdmissionConfig{Verified: &password, OAuth: &oauth}
	frozen := copySingleFactorAdmission(selection)
	repository := &Repository{revokeAdmission: &frozen}
	password.AuthenticationMethod, oauth.AuthenticationMethod = "unselected", "unselected"
	for name, record := range map[string]session.Session{"password": passwordSession, "oauth": providerSession} {
		t.Run(name, func(t *testing.T) {
			admission, err := repository.revokeRecordAdmission(record, command.Binding)
			if err != nil || admission.credential == nil || admission.oauth != (name == "oauth") {
				t.Fatal("stored method must select its frozen owner without fallback", err)
			}
			if name == "oauth" && admission.credential.Credential != account.Credential.Credential {
				t.Fatal("OAuth revocation lost original linked credential")
			}
		})
	}
	frozen.OAuth = nil
	if _, err := repository.revokeRecordAdmission(providerSession, command.Binding); err == nil {
		t.Fatal("unselected OAuth session fell back to password")
	}
}
