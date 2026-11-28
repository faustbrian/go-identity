package impersonationpostgres

import (
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestPendingDenialPolicyBindsActorTargetGrantAndScope(t *testing.T) {
	command := m24PolicyCommand(t)
	grant := m24PolicyCommand(t)
	scope, err := impersonation.NewScope([]string{"profile.read"})
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{
		CommandID: command, TenantID: "tenant-a", UserID: "target", ActorID: "independent-admin",
		ActorKind: authorization.SubjectUser, OperationID: "identity.impersonation.deny",
		RecordID: string(grant), PolicyID: "support", PolicyVersion: 1,
		SchemaID: "impersonation-deny", SchemaVersion: 1, CorrelationID: string(command),
	}
	decision, err := actorDecision(binding, scope, time.Now().UTC())
	if err != nil {
		t.Fatalf("denial has no distinct authorization boundary: %v", err)
	}
	request := decision.Request
	permissions, _ := request.Attributes["impersonation.scope"].StringSet()
	grantID, _ := request.Attributes["impersonation.grant-id"].String()
	if request.Action != "identity.impersonation.deny" || request.Subject.Kind != authorization.SubjectUser ||
		request.Subject.ID != "independent-admin" || request.Tenant != "tenant-a" ||
		request.Resource.Type != "identity.user" || request.Resource.ID != "target" ||
		grantID != string(grant) || !slices.Equal(permissions, []string{"profile.read"}) {
		t.Fatal("denial policy did not observe the exact actor, target, grant and requested scope")
	}
}

func m24PolicyCommand(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
