package postgres

import (
	"context"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type ssoOIDCSigninAccountParticipant struct{ scopeFeatureParticipant }

func (*ssoOIDCSigninAccountParticipant) Descriptor() ContributorDescriptor {
	return ssoOIDCSigninDescriptor()
}

func ssoOIDCSigninAccountFixture() ProviderAccountAdmission {
	a := signinAccountFixture()
	a.Account.Provider = "sso-organization-provider"
	a.Credential.Credential.Owner = "sso"
	return a
}

func ssoOIDCSigninAccountCommand(t *testing.T, a ProviderAccountAdmission) (identity.FeatureCommandSpec, identity.Command) {
	t.Helper()
	b, _ := ssoOIDCSigninPlanFixture(t)
	b.TenantID = a.Account.TenantID
	s := featureCodecSpec()
	s.Operation, s.Binding = ssoOIDCSigninOperation(), b
	var err error
	s.Fields, err = SSOOIDCSigninAccountFields(a)
	if err != nil {
		t.Fatal("enterprise snapshot", err)
	}
	return s, ssoOIDCAccountPreAuthCommand(t, s)
}

func ssoOIDCAccountPreAuthCommand(t *testing.T, s identity.FeatureCommandSpec) identity.Command {
	t.Helper()
	c, err := identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal("enterprise command", err)
	}
	return c
}

func TestSSOOIDCSigninAccountFreezesExactEnterpriseSnapshot(t *testing.T) {
	expected := ssoOIDCSigninAccountFixture()
	s, command := ssoOIDCSigninAccountCommand(t, expected)
	if got, err := SSOOIDCSigninAccount(command); err != nil || got != expected {
		t.Fatal("enterprise account snapshot lost", err)
	}
	for _, field := range s.Fields {
		for _, mode := range []string{"missing", "mistyped"} {
			t.Run(field.Name+"/"+mode, func(t *testing.T) {
				changed := s
				changed.Fields = append([]identity.FeatureField(nil), s.Fields...)
				for i := range changed.Fields {
					if changed.Fields[i].Name != field.Name {
						continue
					}
					if mode == "missing" {
						changed.Fields = append(changed.Fields[:i], changed.Fields[i+1:]...)
					} else {
						changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}
					}
					break
				}
				if _, err := SSOOIDCSigninAccount(ssoOIDCAccountPreAuthCommand(t, changed)); err == nil {
					t.Fatal("incomplete enterprise account admitted")
				}
			})
		}
	}
	if _, err := OAuthSigninAccount(command); err == nil {
		t.Fatal("enterprise profile admitted by social decoder")
	}
	socialSpec, social := signinAccountCommand(t, signinAccountFixture())
	if _, err := SSOOIDCSigninAccount(social); err == nil {
		t.Fatal("social profile admitted by enterprise decoder")
	}
	socialSpec.Fields = append(socialSpec.Fields, identity.FeatureField{Name: "sso.oidc.signin.account.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
	if _, err := OAuthSigninAccount(ssoOIDCAccountPreAuthCommand(t, socialSpec)); err == nil {
		t.Fatal("mixed enterprise namespace admitted by social decoder")
	}
	for _, custody := range []string{"metadata-only", "session-token"} {
		var candidate identity.Command
		var err error
		if custody == "metadata-only" {
			candidate, err = identity.NewFeatureCommand(s)
		} else {
			candidate, err = identity.NewFeatureSessionCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		}
		if err != nil {
			t.Fatal("foreign custody fixture", err)
		}
		if _, err := SSOOIDCSigninAccount(candidate); err == nil {
			t.Fatal("enterprise snapshot admitted without preauth custody", custody)
		}
	}
	for _, edit := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "not-a-start-command" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "sso.oidc.signin.account.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "oauth.signin.account.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
		},
	} {
		changed := s
		changed.Fields = append([]identity.FeatureField(nil), s.Fields...)
		edit(&changed)
		if _, err := SSOOIDCSigninAccount(ssoOIDCAccountPreAuthCommand(t, changed)); err == nil {
			t.Fatal("foreign or mixed enterprise scope admitted")
		}
	}
	for _, owner := range []string{"identity/oauth", "other"} {
		changed := expected
		changed.Credential.Credential.Owner = owner
		if fields, err := SSOOIDCSigninAccountFields(changed); err == nil || fields != nil {
			t.Fatal("non-enterprise credential accepted")
		}
	}
}

// This defensive known-owner fixture never runs SQL. It checks the original
// command custody boundary, not a simulated successful coordinator execution.
func TestSSOOIDCSigninAccountRequiresOriginalNativeInvocation(t *testing.T) {
	for _, mode := range []string{"zero-work", "nil-context", "cancelled", "foreign-owner", "reconstructed", "final-reconstructed", "wrong-descriptor", "wrong-lifecycle", "returned", "admission-only"} {
		t.Run(mode, func(t *testing.T) {
			s, command := ssoOIDCSigninAccountCommand(t, ssoOIDCSigninAccountFixture())
			owner := &ssoOIDCSigninAccountParticipant{}
			_, plan := ssoOIDCSigninPlanFixture(t)
			frozen := &admittedKernelPlan{binding: s.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
			w := Work{state: &workState{ctx: context.Background(), binding: s.Binding, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, execution: &domainExecution{reservation: reservation}}}
			candidate, participant, ctx := command, FeatureExecutionContributor(owner), context.Background()
			switch mode {
			case "zero-work":
				w = Work{}
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign-owner":
				participant = &ssoOIDCSigninAccountParticipant{}
			case "reconstructed", "final-reconstructed":
				candidate = ssoOIDCAccountPreAuthCommand(t, s)
				if mode == "final-reconstructed" {
					w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
				}
			case "wrong-descriptor":
				plan.Feature.Contributor.ContractID = "identity.oauth.signin"
			case "wrong-lifecycle":
				w.state.lifecycle.plan.BeforeVersion = 0
			case "returned":
				w.state.featureInvocation = nil
			case "admission-only":
				w.state.featureApplying = false
			}
			if now, err := w.RequireSSOOIDCSigninProviderAccount(ctx, participant, candidate); err == nil || !now.IsZero() {
				t.Fatal("unowned enterprise account admitted")
			}
			if w.state != nil && (w.state.sqlStarted || w.state.failed == nil || w.state.binding != s.Binding) {
				t.Fatal("invalid admission reached SQL, retargeted or remained usable")
			}
		})
	}
}

func TestSSOOIDCSigninAccountReadRejectsUnownedRepository(t *testing.T) {
	q := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "sso-organization-provider", Issuer: "https://issuer.example", Subject: "subject"}
	for _, r := range []*Repository{nil, {}} {
		if out, err := r.GetSSOOIDCSigninAccount(context.Background(), q); err == nil || out != (ProviderAccountAdmission{}) {
			t.Fatal("unowned enterprise read admitted")
		}
	}
}
