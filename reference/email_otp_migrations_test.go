package reference

import (
	"context"
	"testing"
	"time"

	otppg "github.com/faustbrian/go-identity/otp/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestEmailOTPSelectedHistoryDoesNotRequireOTPSignin(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", global: "deployment"}
	state := &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c, email: &emailState{otpVerification: &otppg.EmailVerificationService{}}}}
	before, err := (StoreSet{state: state}).MigrationSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, step := range before {
		if step.Version() == 1400 {
			found = true
		}
	}
	if !found {
		t.Fatal("selected email OTP omitted native consuming custody without unrelated OTP signin")
	}
	records := make([]migrations.Record, len(before))
	for n, step := range before {
		records[n], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	state.features.migrations.signinSchema = "session_store"
	after, err := (StoreSet{state: state}).MigrationSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := migrations.PlanUp(after, records)
	if err != nil {
		t.Fatal("later OTP signin rewrote installed email OTP custody history", err)
	}
	for _, step := range plan.Steps() {
		if step.Migration().Version() == 1400 {
			t.Fatal("later OTP signin reinstalled native custody")
		}
	}
}
