package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestCleanupRejectsZeroComposition(t *testing.T) {
	if service, err := NewCleanupService(nil, CleanupServiceConfig{}); err == nil || service != nil {
		t.Fatal("zero cleanup composition admitted")
	}
	for _, service := range []*CleanupService{nil, {}} {
		if got, err := service.CleanupExpired(context.Background(), CleanupCommand{}); err == nil || got.Deleted != 0 || got.Command.Binding.CommandID != "" {
			t.Fatal("zero cleanup command admitted")
		}
	}
}

func TestCleanupIntentAndConfigurationBounds(t *testing.T) {
	b := revokeBinding()
	op := cleanupOperation()
	b.RecordID, b.OperationID, b.SchemaID, b.ActorKind = "", op.OperationID, op.SchemaID, authorization.SubjectServiceAccount
	for _, limit := range []uint32{1, 10000} {
		command, err := cleanupIntent(b, limit)
		if err != nil {
			t.Fatal(err)
		}
		if got, size, err := nativeCleanup(command); err != nil || got != b || size != limit {
			t.Fatal("cleanup intent lost exact scope/limit", err)
		}
		for _, mutate := range []func(*identity.FeatureCommandSpec){
			func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectUser },
			func(s *identity.FeatureCommandSpec) { s.Fields = nil },
			func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "unknown" },
			func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Uint64 = 10001 },
			func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Uint64 = 0 },
		} {
			spec, _ := command.Feature()
			mutate(&spec)
			if changed, err := identity.NewFeatureCommand(spec); err == nil {
				if _, _, err := nativeCleanup(changed); err == nil {
					t.Fatal("open cleanup intent admitted")
				}
			}
		}
	}
	for _, limit := range []uint32{0, 10001, math.MaxUint32} {
		if _, err := cleanupIntent(b, limit); err == nil {
			t.Fatal("unbounded cleanup intent admitted")
		}
		if _, err := NewCleanupService(nil, CleanupServiceConfig{ActorID: "worker", MaximumBatch: limit}); err == nil {
			t.Fatal("unbounded cleanup configuration admitted")
		}
	}
	for _, value := range []any{CleanupService{}, CleanupServiceConfig{ActorID: "private-actor"}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("runtime cleanup configuration exported")
		}
		if fmt.Sprintf("%#v", value) != "postgres.CleanupService(redacted)" && fmt.Sprintf("%#v", value) != "postgres.CleanupServiceConfig(redacted)" {
			t.Fatal("runtime cleanup configuration disclosed")
		}
	}
}

func TestCleanupMigrationInputAndCancellation(t *testing.T) {
	for _, source := range []CleanupMigrationSource{{}, {Schema: "public", Version: 1}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxUint64)}} {
		if _, err := source.Load(context.Background()); err == nil {
			t.Fatal("invalid cleanup migration admitted")
		}
	}
	valid := CleanupMigrationSource{Schema: "session_store", Version: 22}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := valid.Load(cancelled); err == nil {
		t.Fatal("cancelled migration admitted")
	}
	if _, err := valid.Load(nil); err == nil {
		t.Fatal("nil migration context admitted")
	}
	if got, err := valid.Load(context.Background()); err != nil || len(got) != 1 {
		t.Fatal("forward cleanup migration unavailable", err)
	}
}
