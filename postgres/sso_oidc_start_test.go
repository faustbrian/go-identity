package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type enterpriseOIDCLinkStartAdmission struct{ denied bool }

func (a enterpriseOIDCLinkStartAdmission) Check(context.Context) error {
	if a.denied {
		return identity.ForbiddenError{}
	}
	return nil
}

func (enterpriseOIDCLinkStartAdmission) Generate(context.Context, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}

func TestEnterpriseOIDCLinkStartRequiresRetainedAdmissionInWork(t *testing.T) {
	for name, invalidate := range map[string]func(*reservationState){
		"preparation": func(r *reservationState) { r.preparation = nil },
		"admission":   func(r *reservationState) { r.preparation.admission = nil },
		"output":      func(r *reservationState) { r.preparation.ciphertext = nil },
		"generation":  func(r *reservationState) { r.preparation.generation = 0 },
		"request":     func(r *reservationState) { r.executionRequest = nil },
		"denied":      func(r *reservationState) { r.preparation.admission = enterpriseOIDCLinkStartAdmission{denied: true} },
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := preparationOutputFixture(t)
			r := w.state.execution.reservation
			r.plan.feature.Operation = SSOOIDCExplicitLinkStartOperation()
			r.preparation.admission = enterpriseOIDCLinkStartAdmission{}
			c := w.state.execution.coordinator
			if err := c.checkPreparedAdmission(w); err != nil {
				t.Fatal("original member with intact admission denied", err)
			}
			invalidate(r)
			if c.checkPreparedAdmission(w) == nil {
				t.Fatal("explicit member start admitted Work without intact original preparation")
			}
		})
	}
}

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

func TestEnterpriseOIDCLinkStartBindsItsOriginalMember(t *testing.T) {
	b, original, final := enterpriseOIDCStartPlans(t)
	op := SSOOIDCExplicitLinkStartOperation()
	b.SchemaID, b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = op.SchemaID, "member-id", "", "member-id", authorization.SubjectUser
	for _, p := range []*CommandPlan{&original, &final} {
		p.Feature.Operation = op
	}
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("authenticated enterprise link cannot attach its original callback grant")
	}
	meta := final.CapabilityIssuance.Grants[0]
	issued := meta.ExpiresAt.Add(-time.Minute)
	x := capability.Payload{Version: 1, ID: meta.CapabilityID, Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID,
		CorrelationID: b.CorrelationID, Operation: ssoOIDCSigninPurpose, MaxUses: 1, IssuedAt: issued, NotBefore: issued, ExpiresAt: meta.ExpiresAt}
	if subject, err := oauthRPInitiationGrantSubject(b, final, x); err != nil || subject != string(b.UserID) {
		t.Fatal("callback grant did not preserve the member's explicit consent scope", err)
	}
	wrong := x
	wrong.Subject = "different-member"
	if _, err := oauthRPInitiationGrantSubject(b, final, wrong); err == nil {
		t.Fatal("substituted member obtained a grant")
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op}
	credential := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	sessionCommand, err := identity.NewFeatureSessionCommand(spec, credential)
	if err != nil || !validSSOOIDCExplicitLinkStartCommand(sessionCommand, original) {
		t.Fatal("native initiation refused original session custody", err)
	}
	preauth, err := identity.NewFeaturePreAuthCommand(spec, credential)
	if err != nil || validSSOOIDCExplicitLinkStartCommand(preauth, original) {
		t.Fatal("anonymous browser possession could initiate an authenticated link", err)
	}
	b.ActorID = "other-member"
	if preparationFinalDeclaration(b, original, final) {
		t.Fatal("another actor could initiate the original member's enterprise link")
	}
}
