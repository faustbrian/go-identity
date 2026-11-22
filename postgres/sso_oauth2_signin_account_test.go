package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type ssoOAuth2SigninAccountParticipant struct{ scopeFeatureParticipant }

func (*ssoOAuth2SigninAccountParticipant) Descriptor() ContributorDescriptor {
	return ssoOAuth2SigninDescriptor()
}

func TestSSOOAuth2SigninAccountBindsOnlyOriginalProviderSnapshot(t *testing.T) {
	expected := ssoOIDCSigninAccountFixture()
	spec, command := ssoOAuth2SigninAccountCommand(t, expected)
	if got, err := SSOOAuth2SigninAccount(command); err != nil || got != expected {
		t.Fatal("original OAuth account snapshot did not round-trip", err)
	}
	for _, foreign := range []func(identity.Command) (ProviderAccountAdmission, error){SSOOIDCSigninAccount, OAuthSigninAccount} {
		if _, err := foreign(command); err == nil {
			t.Fatal("a foreign decoder admitted the OAuth2 snapshot")
		}
	}
	for _, prefix := range []string{"oauth.signin.account.", "sso.oidc.signin.account."} {
		mixed := spec
		mixed.Fields = append(append([]identity.FeatureField(nil), spec.Fields...), identity.FeatureField{Name: prefix + "user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other-user"}})
		if _, err := SSOOAuth2SigninAccount(ssoOIDCAccountPreAuthCommand(t, mixed)); err == nil {
			t.Fatal("mixed callback account namespace was accepted")
		}
	}
	_, oidc := ssoOIDCSigninAccountCommand(t, expected)
	if _, err := SSOOAuth2SigninAccount(oidc); err == nil {
		t.Fatal("OAuth2 accepted the OIDC operation")
	}
	metadata, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SSOOAuth2SigninAccount(metadata); err == nil {
		t.Fatal("metadata-only command obtained the protected account snapshot")
	}
}

func ssoOAuth2SigninAccountCommand(t *testing.T, account ProviderAccountAdmission) (identity.FeatureCommandSpec, identity.Command) {
	t.Helper()
	b, p := ssoOAuth2SigninPlanFixture(t)
	b.TenantID = account.Account.TenantID
	fields, err := SSOOAuth2SigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: fields}
	return spec, ssoOIDCAccountPreAuthCommand(t, spec)
}

func TestSSOOAuth2SigninConsumptionIsBoundToProtectedApply(t *testing.T) {
	b, plan := ssoOAuth2SigninPlanFixture(t)
	owner := &ssoOAuth2SigninAccountParticipant{}
	frozen := &admittedKernelPlan{binding: b, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}, capability: plan.Capability}
	reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
	w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, oauthSigninStage: oauthSigninStateConsumed, execution: &domainExecution{reservation: reservation}}}
	got, err := w.SSOOAuth2SigninConsumption(owner)
	if err != nil || got.Command != b || got.Plan != *plan.Capability || got.Generation != 1 {
		t.Fatal("armed OAuth2 Apply lost its original grant", err)
	}
	if _, err := w.SSOOIDCSigninConsumption(owner); err == nil {
		t.Fatal("OIDC accepted the OAuth callback grant")
	}
	other := &ssoOAuth2SigninAccountParticipant{}
	if _, err := w.SSOOAuth2SigninConsumption(other); err == nil {
		t.Fatal("foreign owner borrowed the original grant")
	}
	w.state.featureApplying = false
	if _, err := w.SSOOAuth2SigninConsumption(owner); err == nil {
		t.Fatal("callback state escaped synchronous Apply")
	}
}
