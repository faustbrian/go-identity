package identity

import (
	"testing"
)

const anonymousPlaceholderKind = IdentifierKind("anonymous-placeholder")

func TestAnonymousPlaceholderIsAReservedNonContactIdentifier(t *testing.T) {
	placeholder := Identifier{ID: "placeholder", UserID: "guest", Kind: anonymousPlaceholderKind, CanonicalValue: "AAAAAAAAAAAAAAAAAAAAAQ@anonymous.invalid", Version: 1}
	if err := placeholder.Validate("guest"); err != nil {
		t.Fatal("owning anonymous workflow cannot retain a reserved placeholder", err)
	}
	for name, alter := range map[string]func(*Identifier){
		"verified":               func(i *Identifier) { i.Verified = true },
		"primary":                func(i *Identifier) { i.Verified, i.Primary = true, true },
		"deliverable domain":     func(i *Identifier) { i.CanonicalValue = "guest@example.test" },
		"subdomain":              func(i *Identifier) { i.CanonicalValue = "guest@sub.anonymous.invalid" },
		"display contact":        func(i *Identifier) { i.DisplayValue = "guest@example.test" },
		"short opaque id":        func(i *Identifier) { i.CanonicalValue = "guest@anonymous.invalid" },
		"noncanonical opaque id": func(i *Identifier) { i.CanonicalValue = "AAAAAAAAAAAAAAAAAAAAAR@anonymous.invalid" },
		"mailbox normalization":  func(i *Identifier) { i.NormalizationProfile, i.NormalizationVersion = "identity.email.fixture-v1", 1 },
	} {
		t.Run(name, func(t *testing.T) {
			i := placeholder
			alter(&i)
			if i.Validate("guest") == nil {
				t.Fatal("placeholder acquired contact semantics")
			}
		})
	}
}

func TestGenericIdentifierMutationCannotCreateOrPromoteAnonymousPlaceholder(t *testing.T) {
	state, attach, now := identifierFixture()
	attach.Kind, attach.CanonicalValue = anonymousPlaceholderKind, "AAAAAAAAAAAAAAAAAAAAAQ@anonymous.invalid"
	if _, err := ApplyIdentifierChange(state, attach, now); err == nil {
		t.Fatal("generic attachment impersonated anonymous creation")
	}
	state.Identifiers = append(state.Identifiers, Identifier{ID: "guest", UserID: state.User.ID, Kind: anonymousPlaceholderKind, CanonicalValue: attach.CanonicalValue, Version: 1})
	state.Verifications = append(state.Verifications, Verification{IdentifierID: "guest", State: VerificationPending, Version: 1})
	for _, action := range []IdentifierAction{IdentifierVerify, IdentifierVerifyPrimary, IdentifierMakePrimary, IdentifierRemove, IdentifierRestartVerification} {
		change := IdentifierChange{TenantID: state.User.TenantID, UserID: state.User.ID, ID: "guest", Action: action, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
		if _, err := ApplyIdentifierChange(state, change, now); err == nil {
			t.Fatal("generic mutation acquired anonymous placeholder ownership", action)
		}
	}
}
