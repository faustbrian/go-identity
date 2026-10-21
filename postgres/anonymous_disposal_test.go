package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func anonymousDisposalFixture() AnonymousDisposalIntent {
	c := anonymousCreationIntentFixture()
	return AnonymousDisposalIntent{Snapshot: AnonymousDisposalSnapshot{Authority: AnonymousAuthorityRecord{User: identity.User{TenantID: c.Creation.Binding.TenantID, ID: c.Creation.Binding.UserID, Status: identity.StatusActive, Version: 1}, Placeholder: c.Placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}, LegalHoldVersion: 1}, Action: AnonymousDisposeDelete, RetentionPolicyVersion: 1}
}

func TestAnonymousDisposalBindsOriginalOwnershipAndRetention(t *testing.T) {
	encode := func(i AnonymousDisposalIntent) []byte {
		t.Helper()
		fields, err := AnonymousDisposalFields(i)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(wire)
	}
	original := encode(anonymousDisposalFixture())
	for name, change := range map[string]func(*AnonymousDisposalIntent){
		"aggregate":        func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.User.Version++ },
		"user epoch":       func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.UserAuthorityVersion++ },
		"contact epoch":    func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.IdentifierAuthorityVersion++ },
		"credential epoch": func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.CredentialAuthorityVersion++ },
		"hold epoch":       func(i *AnonymousDisposalIntent) { i.Snapshot.LegalHoldVersion++ },
		"retention policy": func(i *AnonymousDisposalIntent) { i.RetentionPolicyVersion++ },
		"anonymize":        func(i *AnonymousDisposalIntent) { i.Action = AnonymousDisposeAnonymize },
		"retain":           func(i *AnonymousDisposalIntent) { i.Action = AnonymousDisposeRetain },
	} {
		t.Run(name, func(t *testing.T) {
			i := anonymousDisposalFixture()
			change(&i)
			if bytes.Equal(original, encode(i)) {
				t.Fatal("changed disposal intent not bound")
			}
		})
	}
	for name, change := range map[string]func(*AnonymousDisposalIntent){
		"no hold epoch":  func(i *AnonymousDisposalIntent) { i.Snapshot.LegalHoldVersion = 0 },
		"held erase":     func(i *AnonymousDisposalIntent) { i.Snapshot.LegalHold = true },
		"blocked":        func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.User.Status = identity.StatusBanned },
		"unknown action": func(i *AnonymousDisposalIntent) { i.Action = "unknown" },
		"no policy":      func(i *AnonymousDisposalIntent) { i.RetentionPolicyVersion = 0 },
		"overflow":       func(i *AnonymousDisposalIntent) { i.Snapshot.Authority.UserAuthorityVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			i := anonymousDisposalFixture()
			change(&i)
			if fields, err := AnonymousDisposalFields(i); err == nil || fields != nil {
				t.Fatal("unsafe disposal admitted")
			}
		})
	}
	held := anonymousDisposalFixture()
	held.Snapshot.LegalHold = true
	held.Action = AnonymousDisposeRetain
	if _, err := AnonymousDisposalFields(held); err != nil {
		t.Fatal("non-erasing retention denied structurally", err)
	}
	if _, err := NewAnonymousDisposalDomain(nil); err == nil {
		t.Fatal("missing owner accepted")
	}
	if _, err := (*AnonymousDisposalDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}, anonymousDisposalFixture()); err == nil {
		t.Fatal("missing Work admitted")
	}
	for _, v := range []any{anonymousDisposalFixture(), AnonymousDisposalSnapshot{}, AnonymousDisposalDomain{}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit disposal serialization")
		}
		if text := fmt.Sprintf("%+v", v); bytes.Contains([]byte(text), []byte("anonymous.invalid")) {
			t.Fatal("disposal diagnostics leaked")
		}
	}
}
