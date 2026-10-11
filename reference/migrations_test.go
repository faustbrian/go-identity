package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpostgres "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSessionSignoutUpgradePreservesAppliedHistory(t *testing.T) {
	ctx := context.Background()
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", signinSchema: "session_store", global: "deployment"}
	state := &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}
	stores := StoreSet{state: state}
	before, err := stores.MigrationSource().Load(ctx)
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
	state.features.migrations.singleSessionRevocation = true
	after, err := stores.MigrationSource().Load(ctx)
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("selected signout omitted native receipt history", err)
	}
	for i, step := range before {
		if after[i] != step {
			t.Fatal("signout rewrote installed history")
		}
	}
	owner, err := (sessionpostgres.RevokeOneMigrationSource{Base: sessionpostgres.RevocationMigrationSource{Base: sessionpostgres.MigrationSource{Schema: c.signinSchema, Version: 1410}, Version: 1411}, Version: 1417}).Load(ctx)
	if err != nil || after[len(after)-1] != owner[len(owner)-1] {
		t.Fatal("signout differs from its native migration owner", err)
	}
	plan, err := migrations.PlanUp(after, records)
	if err != nil || len(plan.Steps()) != 1 {
		t.Fatal("installed signin cannot upgrade to signout", err)
	}
}

func TestSelectedMigrationDeliveryProfiles(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		config := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", global: "deployment",
			cancellation: mask&1 != 0, receiptTracking: mask&2 != 0, receipts: mask&4 != 0, reconciliation: mask&8 != 0}
		stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: config}}}
		history, err := stores.MigrationSource().Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		owner := deliverypostgres.MigrationSource{Base: fixedMigrationSource(history[:34]), Version: 1250, WorkerVersion: 1251, PolicyVersion: 1252, KeyedVersion: 1253, StateVersion: 1254}
		if config.cancellation {
			owner.CancellationVersion = 1255
		}
		if config.receiptTracking || config.receipts || config.reconciliation {
			owner.ReceiptVersion = 1256
		}
		if config.receipts {
			owner.ReceiptCommandVersion = 1257
		}
		if config.reconciliation {
			owner.ReconciliationVersion, owner.ReconciliationCommandVersion, owner.ReconciliationQueryVersion = 1258, 1259, 1260
		}
		expected, err := owner.Load(context.Background())
		if err != nil || len(history) != len(expected)+1 {
			t.Fatalf("delivery profile %d omitted selected owner prerequisites: %v", mask, err)
		}
		for i := range expected {
			if history[i] != expected[i] {
				t.Fatalf("delivery profile %d differs from its public schema owner", mask)
			}
		}
		if _, err := migrations.PlanUp(history, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSelectedFeaturesCannotExportIncompleteMigrationHistory(t *testing.T) {
	stores := StoreSet{state: &storeState{
		config:   VelocityStoreConfiguration{Schema: "risk_store"},
		features: &featureState{},
	}}
	if history, err := stores.MigrationSource().Load(context.Background()); err == nil || len(history) != 0 {
		t.Fatal("selected features exported only legacy migrations without their owned prerequisites")
	}
}

func TestSelectedMigrationRejectsCrossOwnerSchemaCollisions(t *testing.T) {
	for _, config := range []featureMigrationConfig{
		{otpSchema: "same_store", sessionSchema: "same_store", global: "deployment"},
		{otpSchema: "same_store", authenticatedSchema: "same_store", global: "deployment"},
		{otpSchema: "risk_store", sessionSchema: "session_store", global: "deployment"},
		{otpSchema: "otp_store", sessionSchema: "risk_store", global: "deployment"},
		{otpSchema: "otp_store", authenticatedSchema: "risk_store", global: "deployment"},
	} {
		stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: config}}}
		if history, err := stores.MigrationSource().Load(context.Background()); err == nil || len(history) != 0 {
			t.Fatal("cross-owner schema collision exported an un-installable migration history")
		}
	}
}

func TestSelectedMigrationSessionProfiles(t *testing.T) {
	for _, tc := range []struct {
		name, preauth, authenticated string
		count                        int
	}{
		{"preauth_only", "preauth_store", "", 40},
		{"session_only", "", "authenticated_store", 39},
		{"shared_schema", "shared_store", "shared_store", 40},
		{"independent_schemas", "preauth_store", "authenticated_store", 41},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: tc.preauth, authenticatedSchema: tc.authenticated, global: "deployment"}}}}
			history, err := stores.MigrationSource().Load(ctx)
			if err != nil || len(history) != tc.count {
				t.Fatal("selected session profiles omitted or duplicated native prerequisites", err)
			}
			if _, err := migrations.PlanUp(history, nil); err != nil {
				t.Fatal("selected session histories cannot be planned", err)
			}
			if tc.authenticated != "" && tc.authenticated != tc.preauth {
				expected, err := (sessionpostgres.MigrationSource{Schema: tc.authenticated, Version: 1210}).Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, migration := range history {
					if migration == expected[0] {
						found = true
					}
				}
				if !found {
					t.Fatal("authenticated namespace differs from its session owner")
				}
			}
		})
	}
}

func TestSelectedHistoryPreservesPopulatedLegacyPrefix(t *testing.T) {
	ctx := context.Background()
	state := &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}}
	stores := StoreSet{state: state}
	legacy, err := stores.MigrationSource().Load(ctx)
	if err != nil || len(legacy) != 21 {
		t.Fatal("legacy source changed", err)
	}
	records := make([]migrations.Record, len(legacy))
	for i, step := range legacy {
		records[i], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	state.features = &featureState{migrations: featureMigrationConfig{otpSchema: "selected_otp", sessionSchema: "selected_session", global: "selected_deployment", tenants: []identity.TenantID{"tenant_b", "tenant_a"}}}
	selected, err := stores.MigrationSource().Load(ctx)
	if err != nil || len(selected) != 40 {
		t.Fatal("selected source omitted prerequisites", err)
	}
	for i := range legacy {
		if selected[i] != legacy[i] {
			t.Fatal("selected source rewrote applied legacy identity")
		}
	}
	ownerDirectory, err := (kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 1016, GlobalAuthorityID: "selected_deployment", TenantIDs: []identity.TenantID{"tenant_a", "tenant_b"}}).Load(ctx)
	if err != nil || selected[25] != ownerDirectory[len(ownerDirectory)-1] {
		t.Fatal("directory SQL or bootstrap inputs differ from their public owner", err)
	}
	plan, err := migrations.PlanUp(selected, records)
	if err != nil || len(plan.Steps()) != 19 {
		t.Fatal("populated native history cannot upgrade through owner planner", err)
	}
	versions := []migrations.Version{1012, 1013, 1014, 1015, 1016, 1017, 1018, 1100, 1101, 1102, 1103, 1200, 1201, 1250, 1251, 1252, 1253, 1254, 1300}
	for i, step := range selected[len(legacy):] {
		if step.Version() != versions[i] || step.DownSQL() != "" || step.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("selected allocation or migration mode drifted")
		}
	}
	// Caller-owned outputs cannot alter future source identity; bootstrap set
	// ordering is canonical and must not depend on caller slice order.
	selected[0] = selected[len(selected)-1]
	state.features.migrations.tenants = []identity.TenantID{"tenant_a", "tenant_b"}
	again, err := stores.MigrationSource().Load(ctx)
	if err != nil || again[0] != legacy[0] || again[25].Checksum() != selected[25].Checksum() {
		t.Fatal("mutable output or tenant ordering changed source identity", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if history, err := stores.MigrationSource().Load(canceled); !errors.Is(err, context.Canceled) || len(history) != 0 {
		t.Fatal("canceled source exported history", err)
	}
}
