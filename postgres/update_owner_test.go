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

func TestUserUpdateUnitOfWorkAdmission(t *testing.T) {
	var owner UserUpdateUnitOfWork
	if _, e := owner.Execute(context.Background(), identity.Command{}); e == nil {
		t.Fatal("zero update owner executed")
	}
	if _, e := owner.Recover(context.Background(), identity.RecoveryQuery{}); e == nil {
		t.Fatal("zero update owner recovered")
	}
	if value, e := NewUserUpdateUnitOfWork(nil, nil, CreationUnitOfWorkConfig{}); value != nil || e == nil {
		t.Fatal("invalid update composition admitted")
	}
	if fmt.Sprintf("%#v", owner) != "postgres.UserUpdateUnitOfWork(redacted)" {
		t.Fatal("administrative runtime disclosed")
	}
	if data, e := json.Marshal(owner); e == nil || len(data) != 0 {
		t.Fatal("administrative runtime serialized")
	}
}

func TestAdministrativeFieldAndProtectedAuditAdmission(t *testing.T) {
	schema := storageSchema()
	schema.Fields[0].InputPermission = identity.FieldReadWrite
	schema.Fields[1].WriteAuthorization = identity.FieldWriteSelf
	frozen, e := freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if e != nil {
		t.Fatal(e)
	}
	repo := &Repository{attributeSchemas: frozen}
	b := codecBinding()
	b.OperationID = "identity.user.update-admin"
	spec := identity.UpdateUserCommand{Binding: b, ExpectedVersion: 4, Attributes: storageValues()[:1]}
	if _, _, e := repo.prepareAdministrativeAttributes(spec); e != nil {
		t.Fatal("read-write administrative field rejected", e)
	}
	spec.Attributes = storageValues()[1:2]
	if _, _, e := repo.prepareAdministrativeAttributes(spec); e == nil {
		t.Fatal("administrator bypassed self-only scope")
	}
	spec.Binding.ActorKind, spec.Binding.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	if _, _, e := repo.prepareAdministrativeAttributes(spec); e != nil {
		t.Fatal("exact self scope denied", e)
	}
	spec.Binding.SchemaVersion++
	if _, _, e := repo.prepareAdministrativeAttributes(spec); e == nil {
		t.Fatal("unknown administrative schema admitted")
	}
	for _, class := range []string{"committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		r, e := kernelMutationAudit(context.Background(), b, 4, time.Now().UTC().Truncate(time.Microsecond), class)
		if e != nil || r.Action() != "identity.user.update" || r.Attributes()["retention.class"] != "protected" || r.Attributes()["aggregate.before_version"] != "4" {
			t.Fatal("administrative audit lost protected identity", class, e)
		}
		if _, e := AuditBindingDigest(b, r); e != nil {
			t.Fatal("administrative audit binding", e)
		}
		after := "4"
		if class == "committed" {
			after = "5"
		}
		if r.Attributes()["aggregate.after_version"] != after {
			t.Fatal("administrative failure invented successor")
		}
	}
}
