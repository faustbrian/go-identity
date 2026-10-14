package reference

import (
	"reflect"
	"testing"

	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
)

func TestMagicLinkSignupMigrationsPreserveSelectedPrefixes(t *testing.T) {
	for _, password := range []bool{false, true} {
		for _, totp := range []bool{false, true} {
			t.Run(map[bool]string{false: "magic-only", true: "password-first"}[password]+map[bool]string{false: "/single", true: "/totp"}[totp], func(t *testing.T) {
				c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", magicSessionSchema: "session_store", magicMFAChallenge: totp, global: "deployment"}
				s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c, magicRequest: &magicpg.RequestService{}, magicConsume: &magicpg.ConsumeService{}}}}
				before, err := s.migrationCatalog(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if password {
					before, err = passwordSignupMigrationCatalog(t.Context(), before, "risk_store")
					if err != nil {
						t.Fatal(err)
					}
				}
				after, err := magicLinkSignupMigrationCatalog(t.Context(), before)
				if err != nil {
					t.Fatal(err)
				}
				for i := range before {
					if !reflect.DeepEqual(before[i], after[i]) {
						t.Fatal("signup rewrote installed physical history", before[i].namespace)
					}
				}
				want := map[string]bool{"identity_registration": true, "identity_magiclink_registration": true, "identity_magiclink_signup_factors": true}
				for _, h := range after {
					delete(want, h.namespace)
					if h.namespace == "identity_registration" && len(h.history) != map[bool]int{false: 3, true: 4}[password] {
						t.Fatal("passwordless signup installed unrelated verification history or lost existing prefix")
					}
					if h.namespace == "identity_magiclink_registration" && (len(h.history) != 1 || h.history[0].Version() != 1604 || h.owners[1604] != "identity/postgres" || len(h.guards) != 1) {
						t.Fatal("registration extension lacks exact owner/constraints")
					}
					if h.namespace == "identity_magiclink_signup_factors" && (len(h.history) != 1 || h.history[0].Version() != 4 || h.owners[4] != "identity/mfa/postgres" || len(h.guards) != 1) {
						t.Fatal("factor extension conflicts with later continuation/TOTP selection")
					}
				}
				if len(want) != 0 {
					t.Fatal("selected signup prerequisites missing", want)
				}
			})
		}
	}
}
