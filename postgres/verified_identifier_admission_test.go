package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestVerifiedIdentifierAdmissionRejectsMissingWork(t *testing.T) {
	expected := VerifiedIdentifierAdmission{IdentifierID: "original", Kind: identity.IdentifierEmail, IdentifierVersion: 1, VerificationVersion: 1, User: UserAuthorityAdmission{UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}}
	if err := (Work{}).RequireVerifiedIdentifier(context.Background(), nil, expected); err == nil {
		t.Fatal("missing transaction admitted")
	}
}
