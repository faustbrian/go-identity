package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

// This is the kernel's protected current-link fence, not provider proof or a
// social-login journey. Actual provider/capability/session composition remains
// necessary before any consumer can authenticate through this admission.
func TestProviderAccountAdmissionRejectsUnownedScopeBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	newWork := func() Work {
		return Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
	}
	valid := ProviderAccountAdmission{
		Account:           identity.Account{ID: "account-sensitive", TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "provider-sensitive", Version: 7},
		SocialLinkVersion: 11,
		Credential:        CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-ref", TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 13}, UserAuthorityVersion: 17, IdentifierAuthorityVersion: 19, CredentialAuthorityVersion: 23},
	}
	for _, mode := range []string{"zero-account", "foreign-tenant", "foreign-user", "zero-link", "zero-account-version", "zero-credential", "non-provider", "foreign-credential-user", "zero-user-epoch", "nil-context", "foreign-participant"} {
		t.Run(mode, func(t *testing.T) {
			w, expected, ctx, owner := newWork(), valid, context.Background(), FeatureExecutionContributor(native)
			switch mode {
			case "zero-account":
				expected.Account = identity.Account{}
			case "foreign-tenant":
				expected.Account.TenantID = "foreign"
			case "foreign-user":
				expected.Account.UserID = "foreign"
			case "zero-link":
				expected.SocialLinkVersion = 0
			case "zero-account-version":
				expected.Account.Version = 0
			case "zero-credential":
				expected.Credential = CredentialAdmission{}
			case "non-provider":
				expected.Credential.Credential.Kind = identity.CredentialPassword
				expected.Credential.Credential.Owner = "identity/password"
			case "foreign-credential-user":
				expected.Credential.Credential.UserID = "foreign"
			case "zero-user-epoch":
				expected.Credential.UserAuthorityVersion = 0
			case "nil-context":
				ctx = nil
			case "foreign-participant":
				owner = foreign
			}
			if now, err := w.RequireActiveProviderAccount(ctx, owner, expected); err == nil || !now.IsZero() || w.state.sqlStarted {
				t.Fatal("invalid provider-link admission reached SQL or returned authority")
			}
			if w.state.failed == nil {
				t.Fatal("ignored provider-link admission denial left Work usable")
			}
		})
	}
	if now, err := (Work{}).RequireActiveProviderAccount(context.Background(), native, valid); err == nil || !now.IsZero() {
		t.Fatal("zero Work admitted provider-link authority")
	}
	if raw, err := json.Marshal(valid); err == nil || len(raw) != 0 {
		t.Fatal("correlated provider-link admission serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", valid), "sensitive") {
		t.Fatal("provider-link admission exposed account correlation")
	}
}
