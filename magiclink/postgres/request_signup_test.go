package magiclinkpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProspectiveGenerationOwnsFreshOriginalIdentity(t *testing.T) {
	p, selected := signedRequestScopeFixture(t)
	c := p.service.config()
	c.Signup = &SignupConfig{SchemaID: "signup-fields", SchemaVersion: 1, Domain: kernel.MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 9}}
	p.service.config = func() RequestConfig { return c }
	p.request.Intent, p.request.Email = magiclink.SignupIfAllowed, "User@example.test"
	p.canonical = "user@example.test"
	p.selected = selected
	p.selected.recipient = kernel.RecipientRecord{Query: selected.recipient.Query, Suppressed: true}
	p.selected.factor = 0
	if err := p.prepareProspective(context.Background(), 1); err == nil || p.selected.prospective != nil {
		t.Fatal("unadmitted mailbox generated future identity")
	}
	p.prospectiveAvailable = true
	if err := p.prepareProspective(context.Background(), 0); err == nil || p.selected.prospective != nil {
		t.Fatal("unacknowledged generation allocated identity")
	}
	if err := p.prepareProspective(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	i := p.selected.prospective
	if i == nil || i.Creation.Status != identity.StatusActive || i.Identifier.Verified || i.Identifier.Primary || i.Identifier.Version != 1 || i.Identifier.UserID != i.Creation.Binding.UserID || i.Identifier.CanonicalValue != p.canonical || i.Identifier.DisplayValue != string(p.request.Email) || i.ComparisonProfile != "email-v1" || i.EmailPossessionPolicyVersion != 9 || p.selected.factor != 0 || !p.selected.recipient.Suppressed {
		t.Fatal("future intent fabricated current recipient/factor authority")
	}
	if _, err := identity.ParseIdentifierID(string(i.Creation.Binding.UserID)); err != nil {
		t.Fatal("generated user is not canonical", err)
	}
	if _, err := identity.ParseIdentifierID(string(i.Identifier.ID)); err != nil {
		t.Fatal("generated identifier is not canonical", err)
	}
	original, _ := p.original.Feature()
	b := original.Binding
	b.OperationID, b.AnonymousFlowID, b.UserID = "identity.user.create", "", i.Creation.Binding.UserID
	b.SchemaID, b.SchemaVersion = "signup-fields", 1
	if i.Creation.Binding != b {
		t.Fatal("future creation left original request custody")
	}
	if _, err := p.payload(p.selected); err != nil {
		t.Fatal("generated intent cannot issue original signup profile", err)
	}
	before, _ := kernel.MagicLinkRegistrationDigest(*i)
	if err := p.prepareProspective(context.Background(), 1); err == nil {
		t.Fatal("repeated generation replaced original identity")
	}
	after, _ := kernel.MagicLinkRegistrationDigest(*p.selected.prospective)
	if before != after {
		t.Fatal("denied generation changed frozen intent")
	}
}

func TestNativeRequestDeclarationConservesSignupChoice(t *testing.T) {
	p, _ := signedRequestScopeFixture(t)
	f, _ := p.original.Feature()
	flow, _ := p.flow.Bindings()
	plan, err := requestAuditDeclaration(f.Binding, nil, flow.Binding.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	plan.MagicLinkRequestAcceptance = true
	if err := p.ValidateFeatureCommand(p.original, plan); err == nil {
		t.Fatal("signin admitted signup acceptance branch")
	}
	p.request.Intent = magiclink.SignupIfAllowed
	plan.MagicLinkRequestAcceptance = false
	if err := p.ValidateFeatureCommand(p.original, plan); err == nil {
		t.Fatal("signup lost declared neutral branch")
	}
	plan.MagicLinkRequestAcceptance = true
	if err := p.ValidateFeatureCommand(p.original, plan); err != nil {
		t.Fatal("original signup declaration denied", err)
	}
}
