package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func oauthRPPreparationFixture(t *testing.T, anonymous bool) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, final := signupPreparationPlanFixture(t)
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = "original-user", "", "original-user", authorization.SubjectUser
	if anonymous {
		op.OperationID, op.SchemaID, op.SubjectRequirement = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1", identity.FeatureSubjectAnonymousFlow
		b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = "", string(b.CommandID), "oauth-service", authorization.SubjectServiceAccount
	}
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, 1, "original-rp-transaction"
	owner := ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}
	for _, p := range []*CommandPlan{&original, &final} {
		p.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		p.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
		p.Contributors[3] = owner
		p.SubjectType = "oauth_transaction"
		p.Lifecycle = &LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}
	}
	final.CapabilityIssuance.RegistrationUserID = ""
	final.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.callback"
	return b, original, final
}

func TestOAuthRPStateSubjectIsOriginalUserOrAnonymousFlow(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		b, _, final := oauthRPPreparationFixture(t, anonymous)
		meta := final.CapabilityIssuance.Grants[0]
		subject := string(b.UserID)
		if anonymous {
			subject = b.AnonymousFlowID
		}
		payload := capability.Payload{Version: 1, ID: meta.CapabilityID, Subject: subject, Tenant: string(b.TenantID), Resource: b.RecordID, Operation: "identity.oauth.callback", MaxUses: 1, ExpiresAt: meta.ExpiresAt, IssuedAt: meta.ExpiresAt.Add(-10 * time.Minute), NotBefore: meta.ExpiresAt.Add(-10 * time.Minute)}
		got, err := oauthRPInitiationGrantSubject(b, final, payload)
		if err != nil || got != subject {
			t.Fatal("state issuance does not preserve its real original subject kind", err)
		}
		for _, mutate := range []func(*capability.Payload){
			func(p *capability.Payload) { p.Subject = "foreign-subject" },
			func(p *capability.Payload) { p.Tenant = "foreign-tenant" },
			func(p *capability.Payload) { p.Resource = "foreign-transaction" },
			func(p *capability.Payload) { p.Operation = "identity.account.link-token" },
			func(p *capability.Payload) { p.Bearer = true },
			func(p *capability.Payload) { p.MaxUses = 2 },
			func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
			func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Second) },
		} {
			wrong := payload
			mutate(&wrong)
			if got, err := oauthRPInitiationGrantSubject(b, final, wrong); err == nil || got != "" {
				t.Fatal("state grant retargeted original scope or expanded its lifetime")
			}
		}
	}
}

func TestOAuthRPInitiationRetainsOriginalPreparation(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		b, original, final := oauthRPPreparationFixture(t, anonymous)
		if !preparationFinalDeclaration(b, original, final) {
			t.Fatal("closed RP initiation cannot attach its one actual state issuance")
		}
		for _, mutate := range []func(*identity.CommandBinding, *CommandPlan){
			func(_ *identity.CommandBinding, p *CommandPlan) {
				p.CapabilityIssuance.Grants[0].Purpose = "identity.account.link-token"
			},
			func(_ *identity.CommandBinding, p *CommandPlan) {
				p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
			},
			func(_ *identity.CommandBinding, p *CommandPlan) {
				p.CapabilityIssuance.RegistrationUserID = "invented-user"
			},
			func(_ *identity.CommandBinding, p *CommandPlan) {
				p.CapabilityIssuance.ResetRecipientUserID = "invented-user"
			},
			func(_ *identity.CommandBinding, p *CommandPlan) {
				p.Feature.Contributor.ContractID = "identity.oauth.account-link"
			},
			func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Operation.SchemaID = "other-schema" },
			func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "social_provider.linked.v1" },
			func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.BeforeVersion = 1 },
			func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
			func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "" },
			func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectAPIKey },
		} {
			selected, declaration, attached := oauthRPPreparationFixture(t, anonymous)
			mutate(&selected, &attached)
			if preparationFinalDeclaration(selected, declaration, attached) {
				t.Fatal("RP initiation broadened its original scope or issued another purpose")
			}
		}
	}
}
