package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ssoOAuth2SigninPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := ssoOIDCSigninPlanFixture(t)
	op := identity.FeatureOperation{Owner: "sso/oauth2", OperationID: "identity.sso.oauth-callback", SchemaID: "sso-enterprise-oauth2-callback-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	p.Feature.Operation = op
	p.Feature.Contributor.ContractID = "sso.oauth2-login-callback"
	p.Contributors[3] = p.Feature.Contributor
	p.Capability.Purpose = "identity.sso.oauth-callback"
	return b, p
}

func TestSSOOAuth2SigninPlanKeepsOriginalCallbackReservation(t *testing.T) {
	b, original := ssoOAuth2SigninPlanFixture(t)
	fingerprint := [32]byte{7}
	wire, err := encodeFeaturePlan(b, fingerprint, original)
	if err != nil {
		t.Fatal("native OAuth callback could not retain its original one-use declaration", err)
	}
	got, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || got.Feature == nil || *got.Feature != *original.Feature || got.Capability == nil || *got.Capability != *original.Capability || !preparationFinalDeclaration(b, original, got) {
		t.Fatal("original native preparation lost state scope", err)
	}
	encoded, err := encodeFeaturePlan(b, fingerprint, got)
	if err != nil || !bytes.Equal(wire, encoded) {
		t.Fatal("native original declaration did not round-trip", err)
	}
	state, profile := "pending", int16(4)
	obs := commandObservation{fingerprint: fingerprint[:], state: &state, preparationProfile: &profile, declaration: wire}
	recovered, pending, err := observedCommandPlan(b, &original.Feature.Operation, obs)
	if err != nil || !pending || recovered.Capability == nil || *recovered.Capability != *original.Capability {
		t.Fatal("observation did not recover the exact original capability", err)
	}
	changedProof := *got.Capability
	changedProof.ExpiresAt = changedProof.ExpiresAt.Add(time.Second)
	got.Capability = &changedProof
	if preparationFinalDeclaration(b, original, got) {
		t.Fatal("restoration extended original state expiry")
	}
	for _, other := range []func(*testing.T) (identity.CommandBinding, CommandPlan){ssoOIDCSigninPlanFixture, oauthSigninConsumptionPlanFixture} {
		foreign, _ := other(t)
		if _, err := decodeFeaturePlan(foreign, fingerprint, wire); err == nil {
			t.Fatal("foreign callback decoded native OAuth preparation")
		}
	}
}

func TestSSOOAuth2SigninPlanRejectsUnboundOrForeignConsumption(t *testing.T) {
	for name, edit := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"no proof": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Capability = nil
			p.Contributors = p.Contributors[:4]
		},
		"OIDC proof":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.sso.oidc-callback" },
		"social proof": func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.oauth.callback" },
		"OIDC owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "sso.oidc-login-callback"
		},
		"untargeted":   func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "not-an-original-start" },
		"self-bound":   func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = string(b.CommandID) },
		"foreign user": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "other-user" },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := ssoOAuth2SigninPlanFixture(t)
			edit(&b, &p)
			if _, err := encodeFeaturePlan(b, [32]byte{7}, p); err == nil {
				t.Fatal("admitted incomplete or cross-protocol native callback")
			}
		})
	}
}
