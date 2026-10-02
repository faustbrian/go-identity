package session_test

import (
	"errors"
	"fmt"

	"github.com/faustbrian/go-identity/session"
)

func ExampleAuthoritySnapshot_CompareCurrent() {
	// Synthetic structural input, not an authenticated or primary-read result.
	spec := session.AuthoritySnapshotSpec{
		Global:        session.AuthorityBinding{ScopeKey: "global:deployment", Version: 1},
		Tenant:        session.AuthorityBinding{ScopeKey: "tenant:tenant-a", Version: 1},
		User:          session.AuthorityBinding{ScopeKey: "user:tenant-a:user-a", Version: 1},
		Identifier:    session.AuthorityBinding{ScopeKey: "identifier:tenant-a:user-a", Version: 1},
		Credential:    session.AuthorityBinding{ScopeKey: "credential:tenant-a:user-a", Version: 1},
		SessionFamily: session.AuthorityBinding{ScopeKey: "family:tenant-a:family-a", Version: 1},
		Session:       session.AuthorityBinding{ScopeKey: "session:tenant-a:session-a", Version: 1},
		Authorization: session.AuthorityBinding{ScopeKey: "authorization:tenant-a:user-a", Version: 1},
	}
	stored, err := session.NewAuthoritySnapshot(spec)
	if err != nil {
		panic(err)
	}
	spec.Credential.Version++
	current, err := session.NewAuthoritySnapshot(spec)
	if err != nil {
		panic(err)
	}
	// Never replace stored with current to resurrect a stale session.
	err = stored.CompareCurrent(current)
	fmt.Println(errors.Is(err, session.ErrAuthorityMismatch))
	// Output: true
}
