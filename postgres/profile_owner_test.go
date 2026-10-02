package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// Integration coverage drives the complete public service, SQL, replay and
// failure atomicity. This first case also bounds the new composition's zero.
func TestProfileUnitOfWorkZero(t *testing.T) {
	var owner ProfileUnitOfWork
	var _ identity.UnitOfWork = &owner
	if _, err := owner.Execute(context.Background(), identity.Command{}); err == nil {
		t.Fatal("zero profile owner accepted command")
	}
	if _, err := owner.Recover(context.Background(), identity.RecoveryQuery{}); err == nil {
		t.Fatal("zero profile owner accepted recovery")
	}
}

func TestProfileStorageAdmissionAndAuditVersions(t *testing.T) {
	schema := storageSchema()
	schema.Fields[1].WriteAuthorization = identity.FieldWriteSelf
	frozen, err := freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if err != nil {
		t.Fatal(err)
	}
	repo := &Repository{attributeSchemas: frozen, profileSchema: schemaKey{schema.ID, schema.Version}}
	b := codecBinding()
	b.OperationID = "identity.profile.update"
	b.ActorKind = authorization.SubjectUser
	b.ActorID = identity.ActorID(b.UserID)
	spec := identity.ProfileUpdateCommand{Binding: b, ExpectedVersion: 5, Name: "bounded", AdditionalFields: []identity.AttributeUpdate{storageValues()[1]}}
	if _, _, err := repo.prepareProfileAttributes(spec); err != nil {
		t.Fatal("self field rejected", err)
	}
	spec.AdditionalFields = []identity.AttributeUpdate{storageValues()[0]}
	if _, _, err := repo.prepareProfileAttributes(spec); err == nil {
		t.Fatal("administrator field accepted as self")
	}
	spec.AdditionalFields = nil
	spec.Binding.SchemaVersion++
	if _, _, err := repo.prepareProfileAttributes(spec); err == nil {
		t.Fatal("unselected schema admitted")
	}
	for _, class := range []string{"committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		r, err := kernelMutationAudit(context.Background(), b, 5, time.Now().UTC().Truncate(time.Microsecond), class)
		if err != nil || !validKernelAuditRecord(r) || r.Action() != "identity.user.update" || r.Attributes()["aggregate.before_version"] != "5" {
			t.Fatal("profile audit mismatched", class, err)
		}
		after := "5"
		if class == "committed" {
			after = "6"
		}
		if r.Attributes()["aggregate.after_version"] != after {
			t.Fatal("audit invented version", class)
		}
	}
	owner := ProfileUnitOfWork{}
	if fmt.Sprintf("%#v", owner) != "postgres.ProfileUnitOfWork(redacted)" {
		t.Fatal("profile runtime leaked")
	}
	if body, err := json.Marshal(owner); err == nil || len(body) != 0 {
		t.Fatal("profile runtime serialized")
	}
}
