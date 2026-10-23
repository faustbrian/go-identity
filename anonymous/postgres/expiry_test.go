package anonymouspostgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestExpiryMappingRetainsOriginalSubjectWithoutBrowserAuthority(t *testing.T) {
	spec, subject := creationFixture(t)
	want, _ := subject.Record()
	spec.Binding.UserID = want.UserID
	spec.Binding.RecordID = string(want.UserID)
	spec.Binding.AnonymousFlowID = ""
	spec.Binding.ActorKind, spec.Binding.ActorID = authorization.SubjectServiceAccount, "guest-maintenance"
	spec.Binding.OperationID, spec.Binding.SchemaID = "identity.anonymous.expire", "identity.anonymous.expire.native-v1"
	spec.Operation = identity.FeatureOperation{Owner: "identity/anonymous", OperationID: spec.Binding.OperationID, SchemaID: spec.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	var err error
	spec.Fields, err = anonymouspg.ExpiryFields(subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range spec.Fields {
		if !strings.HasPrefix(f.Name, "anonymous.expire.") {
			t.Fatal("expiry shared browser field namespace")
		}
	}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := anonymouspg.ExpirySubject(command)
	actual, _ := got.Record()
	if err != nil || actual != want {
		t.Fatal("original lifecycle changed", err)
	}
	for n := range spec.Fields {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields[:n]...)
		changed.Fields = append(changed.Fields, spec.Fields[n+1:]...)
		c, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := anonymouspg.ExpirySubject(c); err == nil {
			t.Fatal("incomplete original lifecycle admitted")
		}
	}
	spec.Binding.ActorKind, spec.Binding.ActorID = authorization.SubjectUser, identity.ActorID(want.UserID)
	command, err = identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anonymouspg.ExpirySubject(command); err == nil {
		t.Fatal("browser subject granted maintenance custody")
	}
	var repository *anonymouspg.Repository
	if err := repository.StageExpiredDisposal(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("missing protected work admitted")
	}
	if err := repository.RequireExpiredDisposal(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("missing final fence admitted")
	}
	if _, err := repository.RecoverExpiredDisposal(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
		t.Fatal("missing retained recovery admitted")
	}
	if _, err := anonymouspg.ExpiryFields(anonymous.AnonymousSubject{}); err == nil {
		t.Fatal("invalid subject admitted")
	}
}
