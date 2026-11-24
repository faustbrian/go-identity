package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

type samlLogoutRelayIssuePreparationProbe struct{ samlLogoutRelayIssueProbe }

func (*samlLogoutRelayIssuePreparationProbe) ValidateFeaturePreparation(identity.Command, CommandPlan) error {
	return nil
}

func TestSSOSAMLLogoutRelayIssuePreparationKeepsOriginalAuthority(t *testing.T) {
	_, _, spec, intent, _ := samlLogoutRelayIssueFixture(t)
	origin := intent
	origin.RequestDigest = [32]byte{}
	fields, err := SSOSAMLLogoutRelayIssuePreparationFields(origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SSOSAMLLogoutRelayIssuePreparationFields(intent); err == nil {
		t.Fatal("already signed wire was admitted as initial intent")
	}
	initial := spec
	initial.Fields = fields
	original := featureCodecCommand(t, initial)
	for _, tc := range []struct {
		name    string
		edit    func(*SSOSAMLLogoutRelayIssueIntent, *identity.CommandBinding)
		allowed bool
	}{
		{"exact", func(*SSOSAMLLogoutRelayIssueIntent, *identity.CommandBinding) {}, true},
		{"earlier certificate cutoff", func(i *SSOSAMLLogoutRelayIssueIntent, _ *identity.CommandBinding) {
			i.ExpiresAt = i.ExpiresAt.Add(-time.Second)
		}, true},
		{"other provider", func(i *SSOSAMLLogoutRelayIssueIntent, _ *identity.CommandBinding) { i.ProviderID = "other-provider" }, false},
		{"other organization", func(i *SSOSAMLLogoutRelayIssueIntent, _ *identity.CommandBinding) { i.OrganizationID = "other-org" }, false},
		{"later validity", func(i *SSOSAMLLogoutRelayIssueIntent, _ *identity.CommandBinding) {
			i.IssuedAt = i.IssuedAt.Add(time.Second)
			i.ExpiresAt = i.ExpiresAt.Add(time.Second)
		}, false},
		{"other tenant", func(_ *SSOSAMLLogoutRelayIssueIntent, b *identity.CommandBinding) { b.TenantID = "other-tenant" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, s := intent, spec
			tc.edit(&i, &s.Binding)
			s.Fields, err = SSOSAMLLogoutRelayIssueFields(i)
			if err != nil {
				t.Fatal(err)
			}
			generated := featureCodecCommand(t, s)
			if got := sameSSOSAMLLogoutRelayIssueOrigin(original, generated); got != tc.allowed {
				t.Fatalf("same original authority=%t, want %t", got, tc.allowed)
			}
		})
	}
}

func (*samlLogoutRelayIssuePreparationProbe) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func (*samlLogoutRelayIssuePreparationProbe) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidWork()
}

func (*samlLogoutRelayIssuePreparationProbe) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error) {
	return identity.Command{}, CommandPlan{}, invalidWork()
}

func (*samlLogoutRelayIssuePreparationProbe) PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
	return nil, invalidWork()
}

func (*samlLogoutRelayIssuePreparationProbe) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidWork()
}

func TestSSOSAMLLogoutRelayIssuePlansOriginalCodeFreePreparation(t *testing.T) {
	c, phase, finalSpec, _, final := samlLogoutRelayIssueFixture(t)
	owner := &samlLogoutRelayIssuePreparationProbe{*phase}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{final.Contributors[1]}},
		&riskPassiveProbe{registryContributor{final.Contributors[2]}}, owner, &issuancePlanProbe{}}
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	b, op := finalSpec.Binding, finalSpec.Operation
	final.Audits[0].BindingDigest = securityAuditScopeDigest(b, &op, final.SubjectType, b.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	original := final
	original.CapabilityIssuance, original.Contributors = nil, original.Contributors[:4]
	// Initial authority knows the local command and upper bound, but cannot yet
	// know the exact signed redirect digest or its original one-use grant.
	initialSpec := finalSpec
	initialSpec.Fields = append([]identity.FeatureField(nil), finalSpec.Fields[:len(finalSpec.Fields)-1]...)
	initial := featureCodecCommand(t, initialSpec)
	got, err := c.PrepareFeaturePreparationPlan(initial, original)
	if err != nil || got.Digest == ([32]byte{}) || got.CapabilityIssuance != nil {
		t.Fatal("exact code-free logout issue cannot reach acknowledged preparation", err)
	}
	if _, err := c.PrepareCommandPlan(b, initial, original); err == nil {
		t.Fatal("code-free intent selected ordinary issue execution")
	}
	if !preparationFinalDeclaration(b, got, final) {
		t.Fatal("the original intent did not attach its one final logout grant")
	}
	final.CapabilityIssuance.Grants[0].Purpose = "identity.sso.saml-acs"
	if preparationFinalDeclaration(b, got, final) {
		t.Fatal("the logout issue attached a sibling consent purpose")
	}
}
