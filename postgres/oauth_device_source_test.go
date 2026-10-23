package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

func deviceSourceWork(t *testing.T, stage string) (Work, *oauthConsentProbe, CredentialAdmission, UserAuthorizationAdmission) {
	t.Helper()
	_, original, plan, owner, _ := oauthConsentPlanFixture(t)
	s, _ := original.Feature()
	s.Operation = identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server.device-token", SchemaID: "identity.oauth-server.device-token.native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.UserID, s.Binding.AnonymousFlowID = "", s.Binding.RecordID
	s.Binding.ActorKind, s.Binding.ActorID = authorization.SubjectServiceAccount, "screen-client"
	s.Fields = []identity.FeatureField{
		{Name: "oauth.device-source-user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "human-source"}},
		{Name: "oauth.client", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(s.Binding.ActorID)}},
		{Name: "oauth.grant", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.Binding.RecordID}},
	}
	command := featureCodecCommand(t, s)
	plan.Feature.Operation = s.Operation
	w := Work{state: &workState{ctx: t.Context(), binding: s.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner}}
	switch stage {
	case "prepare":
		w.state.featurePreparationCommand = &command
		w.state.featurePreparationPlan = &admittedKernelPlan{binding: s.Binding, feature: plan.Feature}
	case "apply":
		w.state.featureApplying, w.state.featureApplyCommand = true, &command
	case "final":
		w.state.featureCommitCommand = &command
	}
	c := CredentialAdmission{Credential: identity.CredentialRef{ID: "password-source", TenantID: s.Binding.TenantID, UserID: "human-source", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}
	a := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: authorization.TenantID(s.Binding.TenantID), SubjectID: "human-source", PolicyNamespace: "users"}, Version: 19}
	return w, owner, c, a
}

func TestOAuthDeviceGrantSourceRequiresExactClientCommandAndHumanScope(t *testing.T) {
	for _, mode := range []string{"foreign-source", "foreign-policy", "foreign-tenant", "zero-epoch", "zero-policy", "foreign-owner", "returned", "missing-command", "wrong-schema", "wrong-descriptor", "human-actor", "effective-user", "wrong-flow", "wrong-client", "wrong-grant", "wrong-selector", "nil-context", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			w, owner, c, a := deviceSourceWork(t, "apply")
			original := w.state.binding
			ctx := context.Context(t.Context())
			selected := FeatureExecutionContributor(owner)
			switch mode {
			case "foreign-source":
				c.Credential.UserID = "other"
			case "foreign-policy":
				a.Scope.SubjectID = "other"
			case "foreign-tenant":
				c.Credential.TenantID = "other"
			case "zero-epoch":
				c.IdentifierAuthorityVersion = 0
			case "zero-policy":
				a.Version = 0
			case "foreign-owner":
				selected = &oauthConsentProbe{}
			case "returned":
				w.state.featureInvocation = nil
			case "missing-command":
				w.state.featureApplyCommand = nil
			case "wrong-schema":
				w.state.feature.Operation.SchemaID += ".other"
			case "wrong-descriptor":
				w.state.feature.Contributor.Version++
			case "human-actor":
				w.state.binding.ActorKind = authorization.SubjectUser
			case "effective-user":
				w.state.binding.UserID = "human-source"
			case "wrong-flow":
				w.state.binding.AnonymousFlowID = "other"
			case "wrong-client", "wrong-grant", "wrong-selector":
				s, _ := w.state.featureApplyCommand.Feature()
				name := map[string]string{"wrong-client": "oauth.client", "wrong-grant": "oauth.grant", "wrong-selector": "oauth.device-source-user"}[mode]
				for n := range s.Fields {
					if s.Fields[n].Name == name {
						s.Fields[n].Value.Text = "other"
					}
				}
				command := featureCodecCommand(t, s)
				w.state.featureApplyCommand = &command
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			frozen := w.state.binding
			reader, ok := any(w).(interface {
				RequireOAuthDeviceGrantSource(context.Context, FeatureExecutionContributor, CredentialAdmission, UserAuthorizationAdmission) (time.Time, error)
			})
			if !ok {
				t.Fatal("device grant source fence missing; human actor admission cannot substitute")
			}
			at, err := reader.RequireOAuthDeviceGrantSource(ctx, selected, c, a)
			if err == nil || !at.IsZero() || w.state.failed == nil || w.state.sqlStarted || w.state.binding != frozen {
				t.Fatal("foreign device source reached SQL, changed custody or left live Work", err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("source fence lost cancellation", err)
			}
			if mode != "human-actor" && mode != "effective-user" && mode != "wrong-flow" && w.state.binding != original {
				t.Fatal("source lookup relabeled original client")
			}
		})
	}
}
