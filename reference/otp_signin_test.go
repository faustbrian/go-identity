package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOTPSigninSelectionAndGraphLifetime(t *testing.T) {
	for _, features := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if service, err := features.OTPSignin(); err == nil || service != nil {
			t.Fatal("absent OTP signin exposed a service")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained,
		features: &featureState{composed: true, timeout: time.Second, signin: &otppg.SigninService{}}}
	features := FeatureSet{state: state}
	service, err := features.OTPSignin()
	if err != nil || service == nil {
		t.Fatal("selected graph did not expose public signin", err)
	}
	assertDenied := func() {
		t.Helper()
		if _, err := service.Signin(context.Background(), otp.SigninRequest{}); err == nil {
			t.Fatal("inactive graph admitted signin")
		}
		if _, err := service.RecoverSignin(context.Background(), otp.SigninRecoveryRequest{}); err == nil {
			t.Fatal("inactive graph admitted recovery")
		}
		if state.active != 0 {
			t.Fatal("denied operation leaked graph admission")
		}
	}
	assertDenied()
	state.features.ready = true
	// No selected tenant can reach the borrowed native owner.
	assertDenied()
	state.closed = true
	cancel()
	assertDenied()
	if service, err := features.OTPSignin(); err == nil || service != nil {
		t.Fatal("closed graph exported a new signin handle")
	}
}

func TestOTPSigninSourceSelectionAndGraphLifetime(t *testing.T) {
	for _, features := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if reader, err := features.OTPSigninSource(); err == nil || reader != nil {
			t.Fatal("unselected source reader exposed")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second, signin: &otppg.SigninService{}}}
	reader, err := (FeatureSet{state: s}).OTPSigninSource()
	if err != nil || reader == nil {
		t.Fatal("selected source handle absent", err)
	}
	deny := func() {
		t.Helper()
		if source, err := reader.ResolveSigninSource(context.Background(), otp.SigninSourceRequest{}); err == nil || source != (otp.SigninSource{}) {
			t.Fatal("inactive/foreign source exposed")
		}
		if s.active != 0 {
			t.Fatal("source reader leaked graph admission")
		}
	}
	deny()
	s.features.ready = true
	deny()
	s.closed = true
	cancel()
	deny()
	if reader, err := (FeatureSet{state: s}).OTPSigninSource(); err == nil || reader != nil {
		t.Fatal("closed graph exposed source reader")
	}
}

func TestSelectedOTPSigninMigrationOwnership(t *testing.T) {
	for _, schema := range []string{"preauth_store", "authenticated_store", "signin_store"} {
		t.Run(schema, func(t *testing.T) {
			config := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "authenticated_store", signinSchema: schema, global: "deployment"}
			stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: config}}}
			catalog, err := stores.migrationCatalog(context.Background())
			if err != nil {
				t.Fatal("selected signin migration ownership", err)
			}
			if _, err := migrations.PlanUp(catalog[0].history, nil); err != nil {
				t.Fatal("selected native history cannot be planned", err)
			}
			for version, owner := range map[migrations.Version]ModuleID{1400: "identity/otp/postgres", 1411: "identity/session/postgres", 1412: "identity/session/postgres", 1413: "identity/session/postgres", 1414: "identity/session/postgres", 1415: "identity/session/postgres", 1416: "identity/session/postgres"} {
				if catalog[0].owners[version] != owner {
					t.Fatal("selected migration lost its sole native owner", version)
				}
			}
			if _, separate := catalog[0].owners[1410]; separate != (schema == "signin_store") {
				t.Fatal("session base omitted or duplicated")
			}
		})
	}
}

func TestOTPSigninUpgradesPopulatedSendHistory(t *testing.T) {
	for _, schema := range []string{"preauth_store", "authenticated_store", "signin_store"} {
		t.Run(schema, func(t *testing.T) {
			config := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "authenticated_store", global: "deployment", cancellation: true, receipts: true, reconciliation: true}
			stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: config}}}
			before, err := stores.MigrationSource().Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			records := make([]migrations.Record, len(before))
			for i, step := range before {
				records[i], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			stores.state.features.migrations.signinSchema = schema
			after, err := stores.MigrationSource().Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := migrations.PlanUp(after, records); err != nil {
				t.Fatal("consuming selection cannot upgrade existing Send history", err)
			}
			for i := range before {
				if before[i] != after[i] {
					t.Fatal("existing native history changed")
				}
			}
		})
	}
}
