package identity

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
)

func TestAttributesSCIMActionsPreserveFieldPolicy(t *testing.T) {
	for _, action := range []string{"identity.scim.user-replace", "identity.scim.user-patch"} {
		t.Run(action, func(t *testing.T) {
			field := attributeField("label", AttributeString)
			field.WriteAuthorization = FieldWriteSystem
			field.Default = attributeString("must-not-fill")
			p, request := attributeFixture(t, field)
			request.Context.Request.Action = authorization.Action(action)
			request.Context.Request.Subject.Kind = authorization.SubjectServiceAccount
			request.Context.Request.Subject.ID = "scim-connection"
			calls := 0
			p.authorize = attributeDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				if dc.Request.Action != authorization.Action(action) || dc.Request.Subject.Kind != authorization.SubjectServiceAccount || dc.Request.Subject.ID != "scim-connection" {
					t.Fatal("SCIM attribute preparation impersonated another operation or actor")
				}
				calls++
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
			values, err := p.Prepare(context.Background(), request)
			if err != nil || len(values) != 0 || calls == 0 {
				t.Fatal("SCIM preparation rejected its real action or filled create defaults", err)
			}
			request.Updates = []AttributeUpdate{{Name: "label", Value: attributeString("")}}
			values, err = p.Prepare(context.Background(), request)
			if err != nil || len(values) != 1 || values[0].Value.Scalar.String != "" {
				t.Fatal("SCIM explicit empty value lost its typed preparation", err)
			}
			p.authorize = attributeDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				field, _ := dc.Request.Resource.Attributes["identity.field"].String()
				outcome := authorization.Allow
				if field == "label" {
					outcome = authorization.Deny
				}
				return authorization.Decision{Outcome: outcome, Revision: 1}, nil
			})
			if values, err := p.Prepare(context.Background(), request); err == nil || values != nil {
				t.Fatal("SCIM system write bypassed actual policy")
			}
			for _, unsupported := range []string{"identity.scim.user-update", "identity.scim.user-delete", action + ".alias"} {
				request.Context.Request.Action = authorization.Action(unsupported)
				if values, err := p.Prepare(context.Background(), request); err == nil || values != nil {
					t.Fatal("unselected SCIM action acquired field preparation")
				}
			}
		})
	}
}
