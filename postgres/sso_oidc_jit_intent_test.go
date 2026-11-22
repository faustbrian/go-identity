package postgres

import (
	"bytes"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ssoOIDCJITIntentFixture() SSOOIDCJITIntent {
	account := ssoOIDCSigninAccountFixture()
	account.Account.Provider = "sso.oidc.v1." + strings.Repeat("a", 64)
	account.Account.Version, account.SocialLinkVersion, account.Credential.Credential.Version = 1, 1, 1
	account.Credential.UserAuthorityVersion, account.Credential.IdentifierAuthorityVersion, account.Credential.CredentialAuthorityVersion = 1, 1, 1
	return SSOOIDCJITIntent{
		Account: account,
		Email: identity.Identifier{ID: "new-identifier", UserID: account.Account.UserID, Kind: identity.IdentifierEmail,
			CanonicalValue: "new@enterprise.example", DisplayValue: "new@enterprise.example", Verified: true, Version: 1},
		ComparisonProfile: "canonical-email-v1", JITPolicyVersion: 2, MembershipPolicyVersion: 3,
		ValidUntil: time.Date(2026, 11, 22, 15, 0, 20, 0, time.UTC),
	}
}

func TestSSOOIDCJITIntentBindsProspectiveAccountAndPolicy(t *testing.T) {
	intent := ssoOIDCJITIntentFixture()
	field, err := SSOOIDCJITIntentField(intent)
	if err != nil || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("enterprise creation did not produce a digest-only command field", err)
	}
	for name, change := range map[string]func(*SSOOIDCJITIntent){
		"canonical mailbox":  func(i *SSOOIDCJITIntent) { i.Email.CanonicalValue = "other@enterprise.example" },
		"provider subject":   func(i *SSOOIDCJITIntent) { i.Account.Account.Subject = "other-subject" },
		"comparison profile": func(i *SSOOIDCJITIntent) { i.ComparisonProfile = "canonical-email-v2" },
		"jit policy":         func(i *SSOOIDCJITIntent) { i.JITPolicyVersion++ },
		"membership policy":  func(i *SSOOIDCJITIntent) { i.MembershipPolicyVersion++ },
		"original deadline":  func(i *SSOOIDCJITIntent) { i.ValidUntil = i.ValidUntil.Add(time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			modified := intent
			change(&modified)
			changed, err := SSOOIDCJITIntentField(modified)
			if err != nil || changed.Name != field.Name || bytes.Equal(changed.Value.Bytes, field.Value.Bytes) {
				t.Fatal("original prospective intent did not bind changed field", err)
			}
		})
	}
}

func TestSSOOIDCJITIntentRejectsNonInitialAndUnverifiedState(t *testing.T) {
	for name, change := range map[string]func(*SSOOIDCJITIntent){
		"unverified":          func(i *SSOOIDCJITIntent) { i.Email.Verified = false },
		"different user":      func(i *SSOOIDCJITIntent) { i.Email.UserID = "another" },
		"wrong identifier":    func(i *SSOOIDCJITIntent) { i.Email.Kind = identity.IdentifierUsername },
		"already primary":     func(i *SSOOIDCJITIntent) { i.Email.Primary = true },
		"retained reference":  func(i *SSOOIDCJITIntent) { i.Account.Credential.Credential.Version++ },
		"other provider":      func(i *SSOOIDCJITIntent) { i.Account.Account.Provider = "social" },
		"wrong owner":         func(i *SSOOIDCJITIntent) { i.Account.Credential.Credential.Owner = "identity/oauth" },
		"missing membership":  func(i *SSOOIDCJITIntent) { i.MembershipPolicyVersion = 0 },
		"noncanonical expiry": func(i *SSOOIDCJITIntent) { i.ValidUntil = i.ValidUntil.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			intent := ssoOIDCJITIntentFixture()
			change(&intent)
			if field, err := SSOOIDCJITIntentField(intent); err == nil || field.Name != "" {
				t.Fatal("invalid intent yielded a usable enterprise creation field")
			}
		})
	}
}
