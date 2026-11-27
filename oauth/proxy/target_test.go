package oauthproxy

import (
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func TestProductionCallbackConfigIdentifiersMatchEvidenceBinding(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*ProductionCallbackConfig, string)
	}{
		{"production deployment", func(c *ProductionCallbackConfig, value string) { c.ProductionDeployment = value }},
		{"preview deployment", func(c *ProductionCallbackConfig, value string) { c.Targets[0].Deployment = value }},
		{"recipient", func(c *ProductionCallbackConfig, value string) { c.Targets[0].Recipient = value }},
	} {
		for _, tc := range []struct {
			value string
			valid bool
		}{
			{"canonical-1", true},
			{"-leading-hyphen", true},
			{"_leading_underscore", true},
			{"Uppercase", false},
			{"dotted.name", false},
		} {
			t.Run(field.name+"/"+tc.value, func(t *testing.T) {
				fixture := newCallbackFixture(t)
				config := ProductionCallbackConfig{
					ProductionDeployment: "production-a", Codec: fixture.codec,
					Store: fixture.store, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
				}
				field.set(&config, tc.value)
				callback, err := newProductionCallback(config, fixture.provider)
				if tc.valid {
					if err != nil || callback == nil {
						t.Fatalf("evidence-compatible configuration was rejected: %v", err)
					}
				} else if !errors.Is(err, CallbackInvalid) || callback != nil {
					t.Fatalf("evidence-incompatible configuration was accepted: %v", err)
				}
				if fixture.store.reserved != 0 || fixture.provider.attempts != 0 {
					t.Fatal("configuration validation performed callback or provider work")
				}
			})
		}
	}
}

func TestProductionCallbackRecordIdentifiersGateProviderExchange(t *testing.T) {
	type identifierCase struct {
		value    string
		attempts int
	}
	for _, field := range []struct {
		name  string
		set   func(*oauth.ProxyOIDCEvidenceBinding, string)
		cases []identifierCase
	}{
		{"tenant", func(b *oauth.ProxyOIDCEvidenceBinding, value string) { b.TenantID = identity.TenantID(value) }, []identifierCase{
			{"canonical-1", 1},
			{"-leading-hyphen", 1},
			{"_leading_underscore", 1},
			{"01ARZ3NDEKTSV4RRFFQ69G5FAV", 1},
			{"Uppercase", 1},
			{"dotted.name", 1},
			{"", 0},
			{"tenant a", 0},
			{"tenant\x7f", 0},
			{strings.Repeat("a", 129), 0},
		}},
		{"claims profile", func(b *oauth.ProxyOIDCEvidenceBinding, value string) { b.ClaimsProfile = value }, []identifierCase{
			{"canonical-1", 1},
			{"-leading-hyphen", 1},
			{"_leading_underscore", 1},
			{"Uppercase", 0},
			{"dotted.name", 0},
		}},
	} {
		for _, tc := range field.cases {
			t.Run(field.name+"/"+tc.value, func(t *testing.T) {
				fixture := newCallbackFixture(t)
				field.set(&fixture.store.original.Binding, tc.value)
				callback, err := newProductionCallback(ProductionCallbackConfig{
					ProductionDeployment: "production-a", Codec: fixture.codec,
					Store: fixture.store, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
				}, fixture.provider)
				if err != nil {
					t.Fatal(err)
				}
				result, err := callback.Handle(t.Context(), fixture.route, fixture.query)
				if !errors.Is(err, CallbackReconcile) || result.Destination() != "" || len(result.Envelope()) != 0 {
					t.Fatalf("invalid record or ambiguous test exchange released a handoff: %v", err)
				}
				if fixture.store.reserved != 1 || fixture.provider.attempts != tc.attempts || fixture.store.terminal != CallbackNeedsReconciliation {
					t.Fatalf("unexpected effects: reserved %d attempts %d terminal %v", fixture.store.reserved, fixture.provider.attempts, fixture.store.terminal)
				}
				if fixture.store.original.Verifier.Challenge() != "" {
					t.Fatal("callback retained borrowed verifier custody")
				}
			})
		}
	}
}

func TestProductionCallbackConfigPreservesCanonicalDNSRegistrations(t *testing.T) {
	for _, tc := range []struct {
		host  string
		valid bool
	}{
		{"preview.example", true},
		{"preview-1.example", true},
		{"preview.example:8443", true},
		{"under_score.example", false},
		{"-leading.example", false},
		{"trailing-.example", false},
		{"Uppercase.example", false},
		{"xn--preview.example", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			fixture.target.Origin = "https://" + tc.host
			fixture.target.Redirect = fixture.target.Origin + "/complete"
			callback, err := newProductionCallback(ProductionCallbackConfig{
				ProductionDeployment: "production-a", Codec: fixture.codec,
				Store: fixture.store, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
			}, fixture.provider)
			if tc.valid {
				if err != nil || callback == nil {
					t.Fatalf("canonical DNS registration was rejected: %v", err)
				}
			} else if !errors.Is(err, CallbackInvalid) || callback != nil {
				t.Fatalf("noncanonical DNS registration was accepted: %v", err)
			}
		})
	}
}
