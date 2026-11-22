package postgres

import (
	"encoding/base64"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestEnterpriseOAuth2StartAcceptsOnlyPreAuthCredential(t *testing.T) {
	b, initial, _ := enterpriseOAuth2StartPlans(t)
	spec := identity.FeatureCommandSpec{Binding: b, Operation: initial.Feature.Operation}
	credential := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	browser, err := identity.NewFeaturePreAuthCommand(spec, credential)
	if err != nil || !validSSOOAuth2StartCommand(browser, initial) {
		t.Fatal("intact original pre-authentication command denied", err)
	}
	uncredentialed, err := identity.NewFeatureCommand(spec)
	if err != nil || validSSOOAuth2StartCommand(uncredentialed, initial) {
		t.Fatal("OAuth start accepted a command without the pre-authentication credential", err)
	}
}

func TestEnterpriseOAuth2StartCannotApplyWithoutRetainedBrowserAdmission(t *testing.T) {
	for name, invalidate := range map[string]func(*reservationState){
		"preparation": func(r *reservationState) { r.preparation = nil },
		"admission":   func(r *reservationState) { r.preparation.admission = nil },
		"request":     func(r *reservationState) { r.executionRequest = nil },
		"denied":      func(r *reservationState) { r.preparation.admission = enterpriseOIDCLinkStartAdmission{denied: true} },
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := preparationOutputFixture(t)
			r := w.state.execution.reservation
			r.plan.feature.Operation = SSOOAuth2SigninStartOperation()
			r.preparation.admission = enterpriseOIDCLinkStartAdmission{}
			c := w.state.execution.coordinator
			if err := c.checkPreparedAdmission(w); err != nil {
				t.Fatal("intact OAuth browser admission denied", err)
			}
			invalidate(r)
			if c.checkPreparedAdmission(w) == nil {
				t.Fatal("OAuth start admitted Work without its original preparation")
			}
		})
	}
}

func enterpriseOAuth2StartPlans(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, initial, prepared := enterpriseOIDCStartPlans(t)
	op := SSOOAuth2SigninStartOperation()
	owner := ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oauth2-login-start", Version: 1}
	b.SchemaID = op.SchemaID
	for _, p := range []*CommandPlan{&initial, &prepared} {
		p.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		p.Contributors[3] = owner
	}
	prepared.CapabilityIssuance.Grants[0].Purpose = "identity.sso.oauth-callback"
	return b, initial, prepared
}

func TestEnterpriseOAuth2StartKeepsOAuthGrantInAdmissionGatedPreparation(t *testing.T) {
	b, initial, prepared := enterpriseOAuth2StartPlans(t)
	op := prepared.Feature.Operation
	q := claimRequest{feature: &op, purpose: op.OperationID}
	if !ssoEnterpriseStartClaim(q) || !preparationRetainsDeclaration(initial) || !preparationFinalDeclaration(b, initial, prepared) {
		t.Fatal("OAuth-only browser start did not retain its own gated preparation")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*identity.CommandBinding, *CommandPlan)
	}{
		{"missing grant", func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance = nil }},
		{"OIDC grant", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.sso.oidc-callback"
		}},
		{"OIDC owner", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "sso.oidc-login-start"
		}},
		{"social grant", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.callback"
		}},
		{"record swap", func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "other-transaction" }},
		{"human actor", func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, initial, prepared := enterpriseOAuth2StartPlans(t)
			tc.mutate(&b, &prepared)
			if preparationFinalDeclaration(b, initial, prepared) {
				t.Fatal("substituted preparation acquired an OAuth callback grant")
			}
		})
	}
}

func TestEnterpriseOAuth2StartGrantUsesOriginalAnonymousFlow(t *testing.T) {
	b, _, p := enterpriseOAuth2StartPlans(t)
	m := p.CapabilityIssuance.Grants[0]
	i := m.ExpiresAt.Add(-time.Minute)
	grant := capability.Payload{ID: m.CapabilityID, Subject: b.AnonymousFlowID, Tenant: string(b.TenantID),
		Resource: b.RecordID, CorrelationID: b.CorrelationID, Operation: string(m.Purpose), MaxUses: 1, IssuedAt: i, NotBefore: i, ExpiresAt: m.ExpiresAt}
	if subject, err := oauthRPInitiationGrantSubject(b, p, grant); err != nil || subject != b.AnonymousFlowID {
		t.Fatal("original OAuth browser flow did not own the grant", err)
	}
	for _, mutate := range []func(*capability.Payload){
		func(g *capability.Payload) { g.Subject = "other-flow" },
		func(g *capability.Payload) { g.Tenant = "other-tenant" },
		func(g *capability.Payload) { g.CorrelationID = "other-correlation" },
		func(g *capability.Payload) { g.Operation = "identity.sso.oidc-callback" },
		func(g *capability.Payload) { g.Bearer = true },
		func(g *capability.Payload) { g.ExpiresAt = g.ExpiresAt.Add(time.Second) },
	} {
		changed := grant
		mutate(&changed)
		if got, err := oauthRPInitiationGrantSubject(b, p, changed); err == nil || got != "" {
			t.Fatal("substituted grant acquired original flow scope")
		}
	}
}
