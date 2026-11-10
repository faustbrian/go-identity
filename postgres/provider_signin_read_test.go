package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestProviderSigninReadRejectsInvalidScopeAndDisclosure(t *testing.T) {
	query := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "provider", Issuer: "https://issuer.example", Subject: "sensitive-subject"}
	if err := query.Validate(); err != nil {
		t.Fatal("valid provider lookup", err)
	}
	for _, mode := range []string{"tenant", "provider", "issuer", "subject", "oversized", "control"} {
		changed := query
		switch mode {
		case "tenant":
			changed.TenantID = ""
		case "provider":
			changed.Provider = ""
		case "issuer":
			changed.Issuer = "http://issuer.example"
		case "subject":
			changed.Subject = ""
		case "oversized":
			changed.Subject = strings.Repeat("x", 513)
		case "control":
			changed.Subject = "subject\n"
		}
		if err := changed.Validate(); err == nil {
			t.Fatal("invalid lookup admitted", mode)
		}
	}
	for _, repository := range []*Repository{nil, {}} {
		if out, err := repository.GetProviderSigninAccount(context.Background(), query); err == nil || out != (ProviderAccountAdmission{}) {
			t.Fatal("unowned repository admitted lookup")
		}
	}
	if raw, err := json.Marshal(query); err == nil || len(raw) != 0 {
		t.Fatal("provider identity query serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", query), "sensitive") {
		t.Fatal("provider subject disclosed")
	}
}
