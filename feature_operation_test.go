package identity_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func featureOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func featureBinding() identity.CommandBinding {
	return identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.session.issue", PolicyID: "session-policy", PolicyVersion: 1, SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation-a", RecordID: "session-a"}
}

func TestFeatureOperationBindsExactSchemaAndRecordPolicy(t *testing.T) {
	d, b := featureOperation(), featureBinding()
	if d.Validate() != nil || b.ValidateFor(d) != nil {
		t.Fatal("exact registered feature rejected")
	}
	for _, kind := range []authorization.SubjectKind{authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount} {
		b.ActorKind = kind
		if b.ValidateFor(d) != nil {
			t.Fatal("supported actor kind rejected")
		}
	}
	b = featureBinding()
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CommandID = "bad" },
		func(b *identity.CommandBinding) { b.TenantID = "" },
		func(b *identity.CommandBinding) { b.UserID = "" },
		func(b *identity.CommandBinding) { b.ActorID = "" },
		func(b *identity.CommandBinding) { b.ActorKind = "" },
		func(b *identity.CommandBinding) { b.OperationID += "-other" },
		func(b *identity.CommandBinding) { b.PolicyID = "" },
		func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		func(b *identity.CommandBinding) { b.SchemaID += "-other" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.CorrelationID = "" },
		func(b *identity.CommandBinding) { b.RecordID = "" },
		func(b *identity.CommandBinding) { b.RecordID = "bad record" },
		func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		bad := b
		change(&bad)
		var invalid identity.InvalidInputError
		if !errors.As(bad.ValidateFor(d), &invalid) {
			t.Fatal("changed feature scope accepted")
		}
	}
	d.RecordRequirement = identity.FeatureRecordOmitted
	if b.ValidateFor(d) == nil {
		t.Fatal("unexpected record accepted")
	}
	b.RecordID = ""
	if b.ValidateFor(d) != nil {
		t.Fatal("record-free operation rejected")
	}
}

func TestFeatureDescriptorsCannotOpenTheKernelCommandUnion(t *testing.T) {
	for _, operation := range []string{"identity.user.create", "identity.user.update-admin", "identity.profile.update", "identity.account.unlink", "identity.account.link-token", "identity.admin.user-ban", "identity.identifier.attach"} {
		d := featureOperation()
		d.OperationID = operation
		if d.Validate() == nil {
			t.Fatalf("kernel operation %s accepted as feature", operation)
		}
	}
	b := featureBinding()
	if _, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}); e == nil {
		t.Fatal("feature binding accepted as kernel command")
	}
	if (identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Second}).Validate() == nil {
		t.Fatal("feature binding accepted as kernel receipt")
	}
}

func TestFeatureDescriptorRejectsNoncanonicalOrIncompleteIdentity(t *testing.T) {
	for _, change := range []func(*identity.FeatureOperation){
		func(d *identity.FeatureOperation) { d.Owner = "" },
		func(d *identity.FeatureOperation) { d.Owner = "identity" },
		func(d *identity.FeatureOperation) { d.Owner = strings.Repeat("a", 129) },
		func(d *identity.FeatureOperation) { d.Owner = "1identity/session" },
		func(d *identity.FeatureOperation) { d.Owner = "Identity/session" },
		func(d *identity.FeatureOperation) { d.Owner = "identity.session" },
		func(d *identity.FeatureOperation) { d.Owner = "identity//session" },
		func(d *identity.FeatureOperation) { d.Owner = "identity-/session" },
		func(d *identity.FeatureOperation) { d.Owner = "identity/session/" },
		func(d *identity.FeatureOperation) { d.Owner = "identity/session-" },
		func(d *identity.FeatureOperation) { d.OperationID = "" },
		func(d *identity.FeatureOperation) { d.OperationID = "Identity.session.issue" },
		func(d *identity.FeatureOperation) { d.OperationID = "identity..session" },
		func(d *identity.FeatureOperation) { d.OperationID = "identity.session.1issue" },
		func(d *identity.FeatureOperation) { d.OperationID = "identity.session.issué" },
		func(d *identity.FeatureOperation) { d.OperationID = string(make([]byte, 129)) },
		func(d *identity.FeatureOperation) { d.SchemaID = "" },
		func(d *identity.FeatureOperation) { d.SchemaVersion = 0 },
		func(d *identity.FeatureOperation) { d.RecordRequirement = 0 },
		func(d *identity.FeatureOperation) { d.RecordRequirement = 99 },
	} {
		d := featureOperation()
		change(&d)
		if d.Validate() == nil || featureBinding().ValidateFor(d) == nil {
			t.Fatal("malformed operation descriptor accepted")
		}
	}
}

func FuzzFeatureOperation(f *testing.F) {
	f.Add("identity/session", "identity.session.issue")
	f.Add("identity", "identity.user.create")
	f.Add("identity/session-1", "identity.session.issue-1")
	f.Add("identity//session", "identity..session")
	f.Fuzz(func(t *testing.T, owner, operation string) {
		d := featureOperation()
		d.Owner, d.OperationID = owner, operation
		if d.Validate() != nil {
			return
		}
		b := featureBinding()
		b.OperationID = operation
		if b.ValidateFor(d) != nil {
			t.Fatal("valid descriptor cannot bind matching command")
		}
		b.SchemaVersion++
		if b.ValidateFor(d) == nil {
			t.Fatal("changed schema accepted")
		}
	})
}
