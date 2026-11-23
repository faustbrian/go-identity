package postgres

import (
	"encoding/base64"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func samlStartPlans(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, initial, prepared := enterpriseOAuth2StartPlans(t)
	op := SSOSAMLSigninStartOperation()
	owner := ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-login-start", Version: 1}
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	for _, plan := range []*CommandPlan{&initial, &prepared} {
		plan.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		plan.Contributors[3] = owner
		lifecycle := LifecyclePlan{EventType: "sso.saml_transaction.created.v1", AfterVersion: 1}
		plan.Lifecycle = &lifecycle
	}
	prepared.CapabilityIssuance.Grants[0].Purpose = "identity.sso.saml-acs"
	return b, initial, prepared
}

func TestEnterpriseSAMLStartOnlyAttachesOriginalBrowserGrant(t *testing.T) {
	b, initial, prepared := samlStartPlans(t)
	op := SSOSAMLSigninStartOperation()
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op}
	credential := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	original, err := identity.NewFeaturePreAuthCommand(spec, credential)
	if err != nil || !validSSOSAMLStartCommand(original, initial) {
		t.Fatal("exact SAML browser start was not admitted", err)
	}
	uncredentialed, err := identity.NewFeatureCommand(spec)
	if err != nil || validSSOSAMLStartCommand(uncredentialed, initial) {
		t.Fatal("SAML browser start was admitted without its original browser credential", err)
	}
	if op.OperationID != "identity.sso.saml-start" || op == SSOOAuth2SigninStartOperation() ||
		!ssoEnterpriseStartClaim(claimRequest{feature: &op, purpose: op.OperationID}) ||
		!preparationRetainsDeclaration(initial) || !preparationFinalDeclaration(b, initial, prepared) {
		t.Fatal("SAML lost its independently selected start and gated grant")
	}
	g := prepared.CapabilityIssuance.Grants[0]
	issued := g.ExpiresAt.Add(-5 * time.Minute)
	payload := capability.Payload{ID: g.CapabilityID, Subject: b.AnonymousFlowID, Tenant: string(b.TenantID),
		Resource: b.RecordID, CorrelationID: b.CorrelationID, Operation: string(g.Purpose), MaxUses: 1,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: g.ExpiresAt}
	if subject, err := oauthRPInitiationGrantSubject(b, prepared, payload); err != nil || subject != b.AnonymousFlowID {
		t.Fatal("the original SAML flow does not own its grant", err)
	}
	for _, changed := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Subject = "different-browser-flow" },
		func(p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Second); p.NotBefore = p.IssuedAt },
	} {
		substitute := payload
		changed(&substitute)
		if subject, err := oauthRPInitiationGrantSubject(b, prepared, substitute); err == nil || subject != "" {
			t.Fatal("a substituted or overlong browser grant acquired SAML scope")
		}
	}
	prepared.CapabilityIssuance.Grants[0].Purpose = "identity.sso.oauth-callback"
	if preparationFinalDeclaration(b, initial, prepared) {
		t.Fatal("the SAML start acquired sibling OAuth callback authority")
	}
}

func TestEnterpriseSAMLStartRequiresRetainedGatedAdmissionAtWork(t *testing.T) {
	w, _ := preparationOutputFixture(t)
	r := w.state.execution.reservation
	r.plan.feature.Operation = SSOSAMLSigninStartOperation()
	r.preparation.admission = enterpriseOIDCLinkStartAdmission{}
	c := w.state.execution.coordinator
	if err := c.checkPreparedAdmission(w); err != nil {
		t.Fatal("intact SAML admission denied", err)
	}
	r.preparation.admission = nil
	if err := c.checkPreparedAdmission(w); err == nil {
		t.Fatal("SAML admitted Work with no original browser admission")
	}
}
