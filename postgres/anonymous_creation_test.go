package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func anonymousCreationIntentFixture() AnonymousCreationIntent {
	b := codecBinding()
	b.UserID = "AAAAAAAAAAAAAAAAAAAAAQ"
	return AnonymousCreationIntent{
		Creation:    identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()},
		Placeholder: identity.Identifier{ID: "placeholder", UserID: b.UserID, Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: string(b.UserID) + "@anonymous.invalid", Version: 1},
	}
}

func TestAnonymousCreationFieldsConserveKernelIntent(t *testing.T) {
	s := anonymousCreationIntentFixture()
	fields, err := AnonymousCreationFields(s)
	if err != nil || len(fields) != 6 {
		t.Fatal("valid anonymous creation", err)
	}
	encoded := func(fields []identity.FeatureField) []byte {
		t.Helper()
		out, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(out)
	}
	original := encoded(fields)
	for name, change := range map[string]func(*AnonymousCreationIntent){
		"subject": func(s *AnonymousCreationIntent) {
			s.Creation.Binding.UserID = "AAAAAAAAAAAAAAAAAAAAAg"
			s.Placeholder.UserID = s.Creation.Binding.UserID
			s.Placeholder.CanonicalValue = string(s.Creation.Binding.UserID) + "@anonymous.invalid"
		},
		"placeholder id": func(s *AnonymousCreationIntent) { s.Placeholder.ID = "another" },
		"attributes":     func(s *AnonymousCreationIntent) { s.Creation.Attributes[0].Value.Scalar.String = "another guest" },
		"schema":         func(s *AnonymousCreationIntent) { s.Creation.Binding.SchemaID = "another" },
		"schema version": func(s *AnonymousCreationIntent) { s.Creation.Binding.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := anonymousCreationIntentFixture()
			change(&candidate)
			changed, err := AnonymousCreationFields(candidate)
			if err != nil || bytes.Equal(original, encoded(changed)) {
				t.Fatal("changed kernel intent was not bound", err)
			}
		})
	}
	s.Creation.Attributes[0].Value.Scalar.String = "changed after mapping"
	if !bytes.Equal(original, encoded(fields)) {
		t.Fatal("caller changed frozen fields")
	}
	for name, change := range map[string]func(*AnonymousCreationIntent){
		"permanent contact": func(s *AnonymousCreationIntent) { s.Placeholder.Kind = identity.IdentifierEmail },
		"verified":          func(s *AnonymousCreationIntent) { s.Placeholder.Verified = true },
		"primary":           func(s *AnonymousCreationIntent) { s.Placeholder.Primary = true },
		"display":           func(s *AnonymousCreationIntent) { s.Placeholder.DisplayValue = "guest@example.test" },
		"foreign subject":   func(s *AnonymousCreationIntent) { s.Placeholder.UserID = "another" },
		"different opaque local": func(s *AnonymousCreationIntent) {
			s.Placeholder.CanonicalValue = "AAAAAAAAAAAAAAAAAAAAAg@anonymous.invalid"
		},
		"noninitial identifier": func(s *AnonymousCreationIntent) { s.Placeholder.Version++ },
		"nonopaque subject": func(s *AnonymousCreationIntent) {
			s.Creation.Binding.UserID = "named-guest"
			s.Placeholder.UserID = "named-guest"
		},
		"suspended": func(s *AnonymousCreationIntent) { s.Creation.Status = identity.StatusSuspended },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := anonymousCreationIntentFixture()
			change(&candidate)
			if fields, err := AnonymousCreationFields(candidate); err == nil || fields != nil {
				t.Fatal("invalid anonymous kernel intent admitted")
			}
		})
	}
}

func TestAnonymousCreationDoesNotInventAuthority(t *testing.T) {
	if domain, err := NewAnonymousCreationDomain(nil); err == nil || domain != nil {
		t.Fatal("missing kernel repository admitted")
	}
	if user, err := (*AnonymousCreationDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}, anonymousCreationIntentFixture()); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work produced a user")
	}
	if user, placeholder, err := (Work{}).AnonymousCreation(nil); err == nil || user != (identity.User{}) || placeholder != (identity.Identifier{}) {
		t.Fatal("zero Work produced anonymous creation evidence")
	}
	for _, value := range []any{anonymousCreationIntentFixture(), AnonymousCreationDomain{}} {
		if text := fmt.Sprintf("%+v", value); strings.Contains(text, "anonymous.invalid") || strings.Contains(text, "private-value") {
			t.Fatal("anonymous creation diagnostics disclosed private inputs")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("anonymous creation intent serialized")
		}
	}
}
