package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func proxyForwardPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	binding, plan := oauthSigninConsumptionPlanFixture(t)
	op := OAuthProxyForwardOperation()
	binding.OperationID, binding.SchemaID = op.OperationID, op.SchemaID
	binding.RecordID = binding.AnonymousFlowID
	plan.CommandCounters = nil
	plan.SubjectType = "oauth_proxy_transaction"
	plan.Lifecycle = &LifecyclePlan{EventType: "oauth.proxy.completed.v1", BeforeVersion: 1, AfterVersion: 2}
	plan.Audits[0].EventType = "identity.oauth.use_proxy"
	plan.Audits[0].RetentionClass = "protected"
	plan.Capability.Purpose = "identity.oauth.proxy-forward"
	plan.Feature.Operation, plan.Feature.Contributor = op, OAuthProxyForwardDescriptor()
	plan.Contributors = []ContributorDescriptor{plan.Contributors[0], plan.Contributors[1], plan.Contributors[2], plan.Feature.Contributor, plan.Contributors[len(plan.Contributors)-1]}
	return binding, plan
}

func TestOAuthProxyForwardPlanRetainsExactOriginalState(t *testing.T) {
	binding, plan := proxyForwardPlanFixture(t)
	fingerprint := [32]byte{7}
	wire, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("proxy state cannot be selected before provider generation", err)
	}
	decoded, err := decodeFeaturePlan(binding, fingerprint, wire)
	if err != nil || decoded.Capability == nil || *decoded.Capability != *plan.Capability || decoded.Feature == nil || *decoded.Feature != *plan.Feature {
		t.Fatal("history lost the original proxy reservation or native owner", err)
	}
	again, err := encodeFeaturePlan(binding, fingerprint, decoded)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("proxy reservation is not canonical", err)
	}
	if !preparationRetainsDeclaration(plan) || !consumptionAuthenticationPreparation(plan) || !preparationFinalDeclaration(binding, plan, decoded) {
		t.Fatal("proxy generation does not retain the exact preparation declaration")
	}
	for _, change := range []struct {
		name  string
		alter func(*identity.CommandBinding, *CommandPlan)
	}{
		{"local user", func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "local-user" }},
		{"user actor", func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser }},
		{"unrelated flow", func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "unrelated-flow" }},
		{"ordinary provider proof", func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.oauth.callback" }},
		{"missing proof", func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = nil }},
		{"multiple uses", func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 }},
		{"ordinary provider adapter", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.oauth.signin"
		}},
		{"local session effect", func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" }},
		{"alias schema", func(b *identity.CommandBinding, p *CommandPlan) {
			b.SchemaID, p.Feature.Operation.SchemaID = "alias", "alias"
		}},
		{"ordinary callback audit", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Audits[0].EventType = "identity.oauth.handle_callback"
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			b, p := proxyForwardPlanFixture(t)
			change.alter(&b, &p)
			if _, err := encodeFeaturePlan(b, fingerprint, p); err == nil {
				t.Fatal("foreign proxy reservation or mutation effect received a plan")
			}
		})
	}
	_, mutated := proxyForwardPlanFixture(t)
	mutated.Capability.ExpiresAt = mutated.Capability.ExpiresAt.Add(time.Second)
	if preparationFinalDeclaration(binding, plan, mutated) {
		t.Fatal("generation could increase original proof validity")
	}
	ordinary, _ := oauthSigninConsumptionPlanFixture(t)
	if _, err := decodeFeaturePlan(ordinary, fingerprint, wire); err == nil {
		t.Fatal("ordinary sign-in could restore proxy-only history")
	}
}
