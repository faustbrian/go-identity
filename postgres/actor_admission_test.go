package postgres

import (
	"context"
	"errors"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"testing"
	"time"
)

func TestActorAdmissionRequiresExplicitLiveOwnerAndPreservesTargetScope(t *testing.T) {
	var zero Work
	actor, ok := any(zero).(interface {
		RequireActiveActorCredential(context.Context, FeatureExecutionContributor, CredentialAdmission) (time.Time, error)
		RequireActiveActorAuthorization(context.Context, FeatureExecutionContributor, UserAuthorizationAdmission) error
	})
	if !ok {
		t.Fatal("explicit actor admission API missing; target-user admission cannot substitute")
	}
	if at, err := actor.RequireActiveActorCredential(t.Context(), nil, CredentialAdmission{}); err == nil || !at.IsZero() {
		t.Fatal("zero Work admitted actor credential")
	}
	if err := actor.RequireActiveActorAuthorization(t.Context(), nil, UserAuthorizationAdmission{}); err == nil {
		t.Fatal("zero Work admitted actor authorization")
	}
}

func TestActorAdmissionDoesNotBorrowTargetOrForeignAuthority(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	spec.Binding.ActorID, spec.Binding.ActorKind = "human-actor", authorization.SubjectUser
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	for _, mode := range []string{"target-credential", "target-policy", "foreign-tenant", "service-actor", "anonymous", "empty-actor", "foreign-owner", "nil-context", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			b := spec.Binding
			ctx := context.Context(t.Context())
			p := FeatureExecutionContributor(native)
			c := CredentialAdmission{Credential: identity.CredentialRef{ID: "actor-password", TenantID: b.TenantID, UserID: identity.UserID(b.ActorID), Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
			a := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(b.ActorID), PolicyNamespace: "users"}, Version: 1}
			switch mode {
			case "target-credential":
				c.Credential.UserID = b.UserID
			case "target-policy":
				a.Scope.SubjectID = authorization.SubjectID(b.UserID)
			case "foreign-tenant":
				c.Credential.TenantID = "foreign"
				a.Scope.TenantID = "foreign"
			case "service-actor":
				b.ActorKind = authorization.SubjectServiceAccount
			case "anonymous":
				b.UserID = ""
				b.AnonymousFlowID = "flow"
			case "empty-actor":
				b.ActorID = ""
			case "foreign-owner":
				p = foreign
			case "nil-context":
				ctx = nil
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			w := Work{state: &workState{ctx: t.Context(), binding: b, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
			var err error
			if mode == "target-policy" {
				err = w.RequireActiveActorAuthorization(ctx, p, a)
			} else {
				_, err = w.RequireActiveActorCredential(ctx, p, c)
			}
			if err == nil || w.state.failed == nil || w.state.sqlStarted || w.state.binding != b {
				t.Fatal("actor admission borrowed target authority, rewrote scope or failed to poison Work", err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}
