package reference

import (
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func TestOrganizationHTTPSelectsItsOwnAtomicAdmissionHistory(t *testing.T) {
	for _, profile := range []string{"unselected", "safe", "admin", "secret"} {
		t.Run(profile, func(t *testing.T) {
			f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}}
			if profile != "unselected" {
				f.httpOrganization = &organizationHTTPState{}
				switch profile {
				case "safe":
					f.httpOrganization.safe = &identityhttp.SafeRateLimiter{}
				case "admin":
					f.httpOrganization.admin = &organizationhttp.AdminRateLimiter{}
				case "secret":
					f.httpOrganization.secret = &identityhttp.KeyedSecretRateLimiter{}
				}
			}
			// These handles select only migration metadata, not runtime authority.
			s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, httpRate: &httpRateState{}, features: f}}
			catalog, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			native, found := ratepg.AtomicSchemaMigration(), 0
			for _, h := range catalog {
				for _, step := range h.history {
					if step.Name() == native.Name {
						if h.namespace != "identity_http_rate" || step.UpSQL() != native.Up || h.owners[step.Version()] != "rate-limit/postgres" {
							t.Fatal("organization HTTP changed atomic admission ownership")
						}
						found++
					}
				}
			}
			want := 0
			if profile == "admin" || profile == "secret" {
				want = 1
			}
			if found != want {
				t.Fatal("independent organization HTTP admission migration", found, want)
			}
		})
	}
}

func TestOrganizationInvitationsSelectTheirOwnCapabilityHistory(t *testing.T) {
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, organization: &organizationState{invitations: &organizationpg.InvitationService{}}}}}
	base, err := s.baseMigrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := s.organizationMigrationCatalog(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	var capability *migrationHistory
	for i := range catalog {
		if catalog[i].namespace == "identity_capability" {
			if capability != nil {
				t.Fatal("duplicate capability history")
			}
			capability = &catalog[i]
		}
	}
	if capability == nil || len(capability.history) == 0 || len(capability.guards) == 0 {
		t.Fatal("native invitations omitted their capability installation")
	}
	for _, step := range capability.history {
		if capability.owners[step.Version()] != "capability/postgres/identity" {
			t.Fatal("invitation capability history lost native owner")
		}
	}
	// Another selected workflow may already supply the same physical history.
	again, err := s.organizationMigrationCatalog(t.Context(), append(base, *capability))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, h := range again {
		if h.namespace == "identity_capability" {
			found++
			if len(h.history) != len(capability.history) {
				t.Fatal("existing capability prefix changed")
			}
			for i := range h.history {
				if h.history[i] != capability.history[i] {
					t.Fatal("installed capability history was rewritten")
				}
			}
		}
	}
	if found != 1 {
		t.Fatal("invitations duplicated existing capability owner", found)
	}
}
