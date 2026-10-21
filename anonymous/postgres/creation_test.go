package anonymouspostgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func creationFixture(t *testing.T) (identity.FeatureCommandSpec, anonymous.AnonymousSubject) {
	t.Helper()
	id, _ := identity.NewSubjectID()
	commandID, _ := identity.NewCommandID()
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	subject, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: id, TenantID: "tenant-a", UserID: identity.UserID(id), CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupAnonymize})
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: commandID, TenantID: "tenant-a", ActorID: "public-edge", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(commandID), OperationID: "identity.anonymous.signin", SchemaID: "identity.anonymous.signin.native-v1", SchemaVersion: 1, PolicyID: "public-signin", PolicyVersion: 1, CorrelationID: "request"}
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	fields, err := anonymouspg.CreationFields(subject)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, subject
}

func TestCreationMappingRetainsExactOriginalLifecycle(t *testing.T) {
	spec, subject := creationFixture(t)
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := anonymouspg.CreationSubject(command)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := subject.Record()
	actual, _ := got.Record()
	if actual != want {
		t.Fatal("original lifecycle changed")
	}
	for j := range spec.Fields {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields[:j]...)
		changed.Fields = append(changed.Fields, spec.Fields[j+1:]...)
		c, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := anonymouspg.CreationSubject(c); err == nil {
			t.Fatal("incomplete lifecycle mapping accepted")
		}
	}
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "anonymous.subject.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	c, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anonymouspg.CreationSubject(c); err == nil {
		t.Fatal("unknown owned lifecycle input ignored")
	}
}

func TestAnonymousRepositoryCannotManufactureWork(t *testing.T) {
	if r, err := anonymouspg.NewRepository(nil, anonymouspg.Config{Schema: "anonymous_store", MaximumDuration: time.Second}); err == nil || r != nil {
		t.Fatal("missing primary accepted")
	}
	var r *anonymouspg.Repository
	if _, err := r.Read(context.Background(), anonymous.SubjectQuery{}); err == nil {
		t.Fatal("zero reader accepted")
	}
	if err := r.StageCreation(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("unowned lifecycle write accepted")
	}
	if err := r.RequireCreation(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("unowned final lifecycle accepted")
	}
	if _, err := r.RecoverCreation(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
		t.Fatal("unowned lifecycle recovery accepted")
	}
}
