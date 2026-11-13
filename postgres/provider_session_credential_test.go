package postgres

import (
	"context"
	"testing"
)

func TestLinkedProviderSessionCredentialRejectsUnownedScope(t *testing.T) {
	for _, repository := range []*Repository{nil, {}} {
		if err := repository.CheckLinkedProviderCredential(context.Background(), CredentialAdmission{}); err == nil {
			t.Fatal("unowned provider association admitted")
		}
	}
	if err := (Work{}).RequireLinkedProviderCredential(context.Background(), nil, CredentialAdmission{}); err == nil {
		t.Fatal("unowned provider association Work admitted")
	}
}
