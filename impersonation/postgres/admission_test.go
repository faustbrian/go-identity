package impersonationpostgres

import (
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestDecisionBindsAdministratorTargetAndRequestedScope(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := impersonation.NewScope([]string{"profile.read", "address.read"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, name := range []string{requestAction, approveAction, startAction} {
		op, ok := approvalOperation(name)
		if !ok {
			t.Fatalf("missing selected operation %s", name)
		}
		binding := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "target", ActorID: "administrator", ActorKind: authorization.SubjectUser, RecordID: string(id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "privileged", PolicyVersion: 7, CorrelationID: string(id)}
		caller, err := actorDecision(binding, scope, now)
		if err != nil || caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectUser || caller.Request.Subject.ID != "administrator" || caller.Request.Tenant != "tenant" || caller.Request.Action != authorization.Action(name) || caller.Request.Resource.ID != "target" || caller.PolicyRevision != 7 {
			t.Fatalf("decision did not address the actual administrator and exact target: %v", err)
		}
		permissions, ok := caller.Request.Attributes[scopeAttribute].StringSet()
		if !ok || !slices.Equal(permissions, []string{"address.read", "profile.read"}) {
			t.Fatal("decision was made without the selected permissions")
		}
		binding.ActorID = identity.ActorID(binding.UserID)
		if _, err := actorDecision(binding, scope, now); err == nil {
			t.Fatal("target authority substituted for the administrator")
		}
	}
}

func TestStartRegistrationRequiresExplicitActivationService(t *testing.T) {
	start, ok := approvalOperation(startAction)
	if !ok || start.SchemaID != "impersonation-start" || start.SchemaVersion != 1 {
		t.Fatal("activation has no exact canonical owner schema")
	}
	ordinary := &approvalPhase{service: &Service{}}
	enabled := &approvalPhase{service: &Service{activation: &activationService{}}}
	if slices.Contains(ordinary.FeatureOperations(), start) || !slices.Contains(enabled.FeatureOperations(), start) {
		t.Fatal("activation was not exclusive to the selected service")
	}
}
