package identity_test

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ExampleApplyAccountLink() {
	// This is locked primary state, not a caller's claim of provider ownership.
	user := identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 1}
	account := identity.Account{ID: "account", TenantID: "tenant", UserID: "user", Provider: "example", Issuer: "https://issuer.example", Subject: "provider-subject", Version: 1}
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: account, ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}
	state := identity.AccountLinkState{Access: identity.AccountAccessSnapshot{User: user}, Candidate: account, SocialLinkVersion: 1, CredentialVersion: 1}
	next, err := identity.ApplyAccountLink(state, change, time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	// Data-only linking does not manufacture a usable login credential. The
	// platform command owner still authorizes, consumes proof/risk and commits.
	fmt.Println(next.Access.User.Version, next.SocialLinkVersion, next.CredentialVersion, next.AddsCredential)
	// Output: 2 2 1 false
}
