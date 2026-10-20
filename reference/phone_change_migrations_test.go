package reference

import (
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func TestPhoneChangeMigrationsIndependentSelection(t *testing.T) {
	for _, removal := range []bool{false, true} {
		f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignin: &passwordpg.SigninService{}, passwordVerification: &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}}
		if removal {
			f.phoneRemoval = &phoneRemovalState{}
		}
		stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f, httpRate: &httpRateState{}}}
		before, err := stores.migrationCatalog(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f.phoneChange = &phoneChangeState{}
		f.httpPhoneChange = &phoneChangeHTTPState{}
		after, err := stores.migrationCatalog(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		wanted := map[string]bool{"identity_phone_change_cascade": true, "identity_password_phone_change_reauthentication_consumption": true, "identity_otp_phone_purpose": true, "identity_otp_original_consuming_custody": true, ratepg.AtomicSchemaMigration().Name: true}
		seen := map[string]migrationHistory{}
		for _, h := range after {
			if _, ok := seen[h.namespace]; ok {
				t.Fatal("duplicated physical migration namespace", h.namespace)
			}
			seen[h.namespace] = h
			for _, step := range h.history {
				delete(wanted, step.Name())
			}
		}
		if len(wanted) != 0 {
			t.Fatal("independent phone change lacks required owner history", wanted)
		}
		for _, old := range before {
			now, ok := seen[old.namespace]
			if !ok {
				t.Fatal("removed installed owner", old.namespace)
			}
			for i, step := range old.history {
				if i >= len(now.history) || step != now.history[i] {
					t.Fatal("rewrote installed history", old.namespace)
				}
			}
		}
	}
}
