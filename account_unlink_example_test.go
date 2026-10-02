package identity_test

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ExampleApplyAccountUnlink() {
	// Trusted command composition obtains this complete snapshot under its
	// durable locks, after authorization and fresh proof verification.
	state := identity.AccountUnlinkState{
		AccountID: "provider-account", SocialLinkVersion: 1, CredentialVersion: 1,
		Access: identity.AccountAccessSnapshot{
			User:     identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1},
			Accounts: []identity.Account{{ID: "provider-account", TenantID: "tenant-a", UserID: "user-a", Provider: "example", Issuer: "https://issuer.example", Subject: "provider-subject", Version: 1}},
			Methods:  []identity.LoginMethod{{Credential: identity.CredentialRef{ID: "password-a", TenantID: "tenant-a", UserID: "user-a", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true}},
		},
	}
	change := identity.AccountUnlinkChange{TenantID: "tenant-a", UserID: "user-a", AccountID: "provider-account", ExpectedUserVersion: 1, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}
	mutation, err := identity.ApplyAccountUnlink(state, change, time.Unix(100, 0))
	if err != nil {
		panic(err)
	}
	// The durable owner must still persist this with its audit and receipt.
	fmt.Println(len(mutation.Access.Accounts), mutation.TombstoneVersion)
	// Output: 0 2
}
