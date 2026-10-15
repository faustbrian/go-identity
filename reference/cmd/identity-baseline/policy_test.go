package main

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
)

func TestBaselineChangeAdmitsOnlyItsNativeRequestAndSelfScope(t *testing.T) {
	selected, err := baselineAuthorization(false, true)
	if err != nil {
		t.Fatal(err)
	}
	request := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "current-user"}, Action: "identity.password.change", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.change"}}}
	if decision, err := selected.Decide(t.Context(), request); err != nil || decision.Outcome != authorization.Allow {
		t.Fatal("authenticated native password-change admission denied")
	}
	unselected, err := baselineAuthorization(false)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err := unselected.Decide(t.Context(), request); err != nil || decision.Outcome != authorization.Deny {
		t.Fatal("unselected native change request admitted")
	}
	for _, modify := range []func(*authorization.DecisionContext){
		func(r *authorization.DecisionContext) { r.Request.Resource.ID = "identity.user.create" },
		func(r *authorization.DecisionContext) {
			r.Request.Resource = authorization.Resource{Type: "identity.user", ID: "other-user"}
		},
		func(r *authorization.DecisionContext) { r.Request.Subject.ID = "" },
		func(r *authorization.DecisionContext) { r.Request.Tenant = "other-tenant" },
	} {
		other := request
		modify(&other)
		if decision, _ := selected.Decide(t.Context(), other); decision.Outcome == authorization.Allow {
			t.Fatal("change selection expanded native caller/resource authority")
		}
	}
}

func TestBaselinePolicyIsRevisionAndTenantFenced(t *testing.T) {
	service, err := baselineAuthorization(false)
	if err != nil {
		t.Fatal(err)
	}
	request := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: baselineActor},
		Action: "identity.password.signup", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signup"},
	}}
	if decision, err := service.Decide(context.Background(), request); err != nil || decision.Outcome != authorization.Allow {
		t.Fatal("selected public signup denied")
	}
	for _, change := range []func(*authorization.DecisionContext){
		func(c *authorization.DecisionContext) { c.PolicyRevision = 8 },
		func(c *authorization.DecisionContext) { c.Request.Tenant = "other" },
		func(c *authorization.DecisionContext) { c.Request.Subject.ID = "other-service" },
		func(c *authorization.DecisionContext) { c.Request.Action = "identity.password.reset-complete" },
		func(c *authorization.DecisionContext) { c.Request.Resource.ID = "identity.password.signin" },
	} {
		copy := request
		change(&copy)
		if decision, _ := service.Decide(context.Background(), copy); decision.Outcome == authorization.Allow {
			t.Fatal("unselected scope authorized")
		}
	}
	request.Request.Subject = authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}
	request.Request.Action = "identity.session.revoke-one"
	request.Request.Resource = authorization.Resource{Type: "identity.user", ID: "user"}
	if decision, err := service.Decide(context.Background(), request); err != nil || decision.Outcome != authorization.Allow {
		t.Fatal("self signout denied")
	}
	request.Request.Resource.ID = "other-user"
	if decision, _ := service.Decide(context.Background(), request); decision.Outcome == authorization.Allow {
		t.Fatal("cross-user signout authorized")
	}
}
