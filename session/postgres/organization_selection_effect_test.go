package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOrganizationSelectionEffectRequiresExactForeignOwnerAndProfile(t *testing.T) {
	source, _, profile := identifierSessionFixture(t)
	s, _ := source.Bindings()
	b := revokeBinding()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
	op := session.OrganizationSelectionOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	transition, err := session.NewOrganizationSelectionCommand(b, source, session.ActiveOrganizationSelection{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: session.SessionVersion(s.Version)})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := OrganizationSelectionFields(transition, s.LastActivityAt.Add(time.Second).Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := NewOrganizationSelectionEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, OrganizationPasswordSessionAdmission{Profile: profile, Authority: organizationReadAuthority{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []*OrganizationSelectionEffect{nil, effect} {
		if err := effect.Lock(context.Background(), kernel.Work{}, nil, c); err == nil {
			t.Fatal("unowned selection lock admitted")
		}
		if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, c); err == nil {
			t.Fatal("unowned selection write admitted")
		}
		if err := effect.Check(context.Background(), kernel.Work{}, nil, c); err == nil {
			t.Fatal("unowned selection commit admitted")
		}
		if _, err := effect.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned selection recovery admitted")
		}
	}
	if fmt.Sprintf("%#v", effect) != "postgres.OrganizationSelectionEffect(redacted)" {
		t.Fatal("effect disclosed its configuration")
	}
	if _, err := json.Marshal(effect); err == nil {
		t.Fatal("effect serialized")
	}
	for _, p := range []OrganizationPasswordSessionAdmission{{}, {Profile: profile}} {
		if got, err := NewOrganizationSelectionEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, p); err == nil || got != nil {
			t.Fatal("missing organization owner admitted")
		}
	}
	for _, config := range []Config{{}, {Schema: "session_store", MaximumDuration: time.Hour}, {Schema: "bad.schema", MaximumDuration: time.Second}} {
		if got, err := NewOrganizationSelectionEffect(config, OrganizationPasswordSessionAdmission{Profile: profile, Authority: organizationReadAuthority{}}); err == nil || got != nil {
			t.Fatal("invalid native budget/scope admitted")
		}
	}
}

func TestOrganizationSelectionMigrationRejectsInvalidInputs(t *testing.T) {
	for _, source := range []OrganizationSelectionMigrationSource{{}, {Schema: "bad.schema", Version: 100}, {Schema: "session_store"}} {
		if _, err := source.Load(context.Background()); err == nil {
			t.Fatal("invalid session selection migration admitted")
		}
	}
	source := OrganizationSelectionMigrationSource{Schema: "session_store", Version: 100}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); err == nil {
		t.Fatal("cancelled migration loaded")
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil migration context admitted")
	}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 || !strings.Contains(history[0].UpSQL(), `"session_store".organization_selections`) || history[0].DownSQL() != "" {
		t.Fatal("selection history omitted owned forward-only persistence", err)
	}
}
