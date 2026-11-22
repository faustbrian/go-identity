package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
)

func TestNativeRefreshRequestUsesExactSelfAccountAndNoExternalKey(t *testing.T) {
	request := ProviderRefreshRequest{
		TenantID: "tenant", Account: "provider-account", ExpectedVersion: 14, Origin: "https://app.example", Network: "192.0.2.1",
		Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{
			Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"},
			Action: "identity.account.refresh-token", Resource: authorization.Resource{Type: "identity.account", ID: "provider-account"},
		}},
	}
	if err := request.validateScope(request.Origin); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ProviderRefreshRequest){
		"origin":                  func(r *ProviderRefreshRequest) { r.Origin = "https://foreign.example" },
		"tenant":                  func(r *ProviderRefreshRequest) { r.Caller.Request.Tenant = "foreign" },
		"account":                 func(r *ProviderRefreshRequest) { r.Caller.Request.Resource.ID = "different-account" },
		"read instead of refresh": func(r *ProviderRefreshRequest) { r.Caller.Request.Action = "identity.account.get" },
		"client instead of user":  func(r *ProviderRefreshRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		"forwarded chain":         func(r *ProviderRefreshRequest) { r.Network = "192.0.2.1,192.0.2.2" },
		"absent version":          func(r *ProviderRefreshRequest) { r.ExpectedVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			if err := changed.validateScope(request.Origin); err == nil {
				t.Fatal("request could address another refresh scope")
			}
		})
	}
}
