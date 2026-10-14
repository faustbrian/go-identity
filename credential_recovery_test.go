package identity_test

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestPasswordRecoveryAuthorityPreservesDisabledPredecessor(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	ref := identity.CredentialRef{TenantID: "tenant", UserID: "user", ID: "password", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}
	base := identity.CredentialAuthorityRecord{User: identity.User{TenantID: "tenant", ID: "user", Status: identity.StatusActive, Version: 19}, Credential: ref, AuthorityVersion: 13, Enabled: false}
	if identity.CheckPasswordRecoveryAuthority(base, ref, 13, false, now) != nil {
		t.Fatal("disabled password cannot be recovered")
	}
	if identity.CheckCredentialAuthority(base, ref, 13, now) == nil {
		t.Fatal("recovery admitted disabled password authentication")
	}
	for _, enabled := range []bool{false, true} {
		current := base
		current.Enabled = enabled
		if identity.CheckPasswordRecoveryAuthority(current, ref, 13, enabled, now) != nil {
			t.Fatal("exact password predecessor denied")
		}
		if identity.CheckPasswordRecoveryAuthority(current, ref, 13, !enabled, now) == nil {
			t.Fatal("changed enabled predecessor admitted")
		}
	}
	for _, mutate := range []func(*identity.CredentialAuthorityRecord){
		func(r *identity.CredentialAuthorityRecord) { r.User.Status = identity.StatusBanned },
		func(r *identity.CredentialAuthorityRecord) { r.Credential.Version++ },
		func(r *identity.CredentialAuthorityRecord) { r.AuthorityVersion++ },
		func(r *identity.CredentialAuthorityRecord) { r.ExpiresAt = now },
		func(r *identity.CredentialAuthorityRecord) { r.User.TenantID = "foreign" },
	} {
		current := base
		mutate(&current)
		if identity.CheckPasswordRecoveryAuthority(current, ref, 13, false, now) == nil {
			t.Fatal("ineligible recovery predecessor admitted")
		}
	}
	ref.Kind = identity.CredentialAPIKey
	ref.Owner = "identity/apikey"
	base.Credential = ref
	if identity.CheckPasswordRecoveryAuthority(base, ref, 13, false, now) == nil {
		t.Fatal("password recovery admitted other credential kind")
	}
}
