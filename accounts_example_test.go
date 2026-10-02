package identity_test

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ExampleCheckAccountUnlink() {
	// This is an authoritative owner's structural/policy check, not a public
	// client's authorization proof. A durable mutation must repeat it under lock.
	user := identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 2}
	account := identity.Account{ID: "account-a", TenantID: user.TenantID, UserID: user.ID, Provider: "example", Issuer: "https://issuer.example", Subject: "subject-a", Version: 1}
	snapshot := identity.AccountAccessSnapshot{User: user, Accounts: []identity.Account{account}, Methods: []identity.LoginMethod{
		{Credential: identity.CredentialRef{ID: "password-a", TenantID: user.TenantID, UserID: user.ID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true},
	}}
	plan, err := identity.CheckAccountUnlink(snapshot, user.TenantID, user.ID, account.ID, 1, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	fmt.Println(plan.RemainingUsableMethods, plan.InvalidatesCredential)
	// Output: 1 false
}
