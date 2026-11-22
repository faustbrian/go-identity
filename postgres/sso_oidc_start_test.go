package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func enterpriseOIDCStartPlans(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, final := oauthRPPreparationFixture(t, true)
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	owner := ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-start", Version: 1}
	b.OperationID, b.SchemaID, b.ActorID, b.RecordID = op.OperationID, op.SchemaID, "sso-service", string(b.CommandID)
	for _, p := range []*CommandPlan{&original, &final} {
		p.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		p.Contributors[3] = owner
		p.SubjectType = "sso_login_transaction"
	}
	final.CapabilityIssuance.Grants[0].Purpose = "identity.sso.oidc-callback"
	return b, original, final
}

func TestEnterpriseOIDCStartDeclarationKeepsOneExactCallbackGrant(t *testing.T) {
	b, original, final := enterpriseOIDCStartPlans(t)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("enterprise initiation cannot attach its distinct callback state")
	}
	for _, test := range []struct {
		name   string
		mutate func(*identity.CommandBinding, *CommandPlan)
	}{
		{"missing issuance", func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance = nil }},
		{"social callback", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.callback"
		}},
		{"other subject", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.RegistrationUserID = "other-user"
		}},
		{"other protocol", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.sso.oauth-callback"
		}},
		{"foreign owner", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.Owner = "identity/oauth/postgres"
		}},
		{"not the origination record", func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "other-transaction" }},
		{"human instead of preauth actor", func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser }},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, declaration, prepared := enterpriseOIDCStartPlans(t)
			test.mutate(&binding, &prepared)
			if preparationFinalDeclaration(binding, declaration, prepared) {
				t.Fatal("changed declaration acquired callback state issuance")
			}
		})
	}
}

func TestEnterpriseOIDCStateUsesOriginalPreauthScope(t *testing.T) {
	b, _, final := enterpriseOIDCStartPlans(t)
	meta := final.CapabilityIssuance.Grants[0]
	issued := meta.ExpiresAt.Add(-10 * time.Minute)
	x := capability.Payload{Version: 1, ID: meta.CapabilityID, Subject: b.AnonymousFlowID, Tenant: string(b.TenantID), Resource: b.RecordID, CorrelationID: b.CorrelationID, Operation: "identity.sso.oidc-callback", MaxUses: 1, IssuedAt: issued, NotBefore: issued, ExpiresAt: meta.ExpiresAt}
	if subject, err := oauthRPInitiationGrantSubject(b, final, x); err != nil || subject != b.AnonymousFlowID {
		t.Fatal("enterprise state did not preserve original browser flow", err)
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Subject = "another-flow" },
		func(p *capability.Payload) { p.Resource = "another-transaction" },
		func(p *capability.Payload) { p.Tenant = "foreign" },
		func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		func(p *capability.Payload) { p.CorrelationID = "other-correlation" },
		func(p *capability.Payload) { p.Bearer = true },
		func(p *capability.Payload) { p.MaxUses = 2 },
		func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Second); p.NotBefore = p.IssuedAt },
	} {
		invalid := x
		mutate(&invalid)
		if subject, err := oauthRPInitiationGrantSubject(b, final, invalid); err == nil || subject != "" {
			t.Fatal("invalid enterprise grant acquired callback scope")
		}
	}
}
