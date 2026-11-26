package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func oneTapStartPreparationFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, final := oauthRPPreparationFixture(t, true)
	op := identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start",
		SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
	b.ActorKind = authorization.SubjectServiceAccount
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, b.AnonymousFlowID
	owner := ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-initiation", Version: 1}
	for _, p := range []*CommandPlan{&original, &final} {
		p.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		p.Contributors[3] = owner
		p.SubjectType = "preauth_transaction"
		p.Lifecycle = &LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1}
	}
	final.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.onetap-callback"
	return b, original, final
}

func TestOneTapStartPreparationAttachesOnlyItsOriginalFlowCapability(t *testing.T) {
	b, original, final := oneTapStartPreparationFixture(t)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("exact One Tap start cannot attach its one callback capability")
	}
	for _, tt := range []struct {
		name   string
		change func(*identity.CommandBinding, *CommandPlan, *CommandPlan)
	}{
		{"missing capability", func(_ *identity.CommandBinding, _, f *CommandPlan) { f.CapabilityIssuance = nil }},
		{"other purpose", func(_ *identity.CommandBinding, _, f *CommandPlan) {
			f.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.callback"
		}},
		{"user override", func(_ *identity.CommandBinding, _, f *CommandPlan) {
			f.CapabilityIssuance.RegistrationUserID = "invented-user"
		}},
		{"other record", func(b *identity.CommandBinding, _, _ *CommandPlan) { b.RecordID = "different-flow" }},
		{"other owner", func(_ *identity.CommandBinding, a, f *CommandPlan) {
			a.Feature.Contributor.ContractID, f.Feature.Contributor.ContractID = "identity.oauth.rp-initiation", "identity.oauth.rp-initiation"
			a.Contributors[3], f.Contributors[3] = a.Feature.Contributor, f.Feature.Contributor
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, original, final := oneTapStartPreparationFixture(t)
			tt.change(&b, &original, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("invalid One Tap plan could issue a capability")
			}
		})
	}
}

func TestOneTapStartRegistryAndReservationSelectOnlyPreparedNativeOwner(t *testing.T) {
	b, original, final := oneTapStartPreparationFixture(t)
	op, owner := original.Feature.Operation, original.Feature.Contributor
	if !featureContributorOwns(owner, op) || !preparationRetainsDeclaration(original) || !oneTapStartClaim(claimRequest{purpose: b.OperationID, feature: &op}) {
		t.Fatal("the exact registered operation has no retained preparation owner")
	}
	alias := op
	alias.SchemaID += ".alias"
	if featureContributorOwns(owner, alias) || oneTapStartClaim(claimRequest{purpose: b.OperationID, feature: &alias}) {
		t.Fatal("an alternate schema selected native custody")
	}
	wrong := owner
	wrong.Owner = "identity/oauth/onetap/postgres"
	if featureContributorOwns(wrong, op) {
		t.Fatal("the default same-owner rule supplanted the exact native owner")
	}
	coordinator := &Coordinator{}
	if _, _, err := coordinator.ReserveCommand(context.Background(), b, identity.Command{}, final); err == nil || err != invalidPlan() {
		t.Fatal("ordinary reservation did not reject before coordinator work", err)
	}
}

func TestOneTapStartCapabilityCannotExpandItsOriginalScopeOrLifetime(t *testing.T) {
	b, _, final := oneTapStartPreparationFixture(t)
	meta := final.CapabilityIssuance.Grants[0]
	issued := meta.ExpiresAt.Add(-5 * time.Minute)
	payload := capability.Payload{
		Version: 1, ID: meta.CapabilityID, Tenant: string(b.TenantID), Subject: b.AnonymousFlowID, Resource: b.RecordID,
		CorrelationID: b.CorrelationID, Operation: "identity.oauth.onetap-callback", MaxUses: 1,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: meta.ExpiresAt,
	}
	if subject, err := oneTapStartGrantSubject(b, final, payload); err != nil || subject != b.AnonymousFlowID {
		t.Fatal("exact one-use browser grant rejected", err)
	}
	for _, tt := range []struct {
		name   string
		change func(*capability.Payload)
	}{
		{"foreign flow", func(p *capability.Payload) { p.Subject = "foreign-flow" }},
		{"foreign record", func(p *capability.Payload) { p.Resource = "foreign-record" }},
		{"foreign tenant", func(p *capability.Payload) { p.Tenant = "foreign-tenant" }},
		{"other correlation", func(p *capability.Payload) { p.CorrelationID = "other-correlation" }},
		{"generic callback", func(p *capability.Payload) { p.Operation = "identity.oauth.callback" }},
		{"unbound bearer", func(p *capability.Payload) { p.Bearer = true }},
		{"two uses", func(p *capability.Payload) { p.MaxUses = 2 }},
		{"renewed expiry", func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) }},
		{"excess lifetime", func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Second); p.NotBefore = p.IssuedAt }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := payload
			tt.change(&changed)
			if subject, err := oneTapStartGrantSubject(b, final, changed); err == nil || subject != "" {
				t.Fatal("changed browser grant acquired scope or lifetime")
			}
		})
	}
}
