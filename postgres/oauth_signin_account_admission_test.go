package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type oauthSigninAccountParticipant struct{ scopeFeatureParticipant }

func (*oauthSigninAccountParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}
}

func signinAccountFixture() ProviderAccountAdmission {
	return ProviderAccountAdmission{
		Account:           identity.Account{ID: "account", TenantID: "tenant", UserID: "selected-user", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "subject", Version: 5},
		SocialLinkVersion: 7,
		Credential:        CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-ref", TenantID: "tenant", UserID: "selected-user", Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 11}, UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19},
	}
}

func signinAccountCommand(t *testing.T, expected ProviderAccountAdmission) (identity.FeatureCommandSpec, identity.Command) {
	t.Helper()
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID, s.Binding.SchemaVersion = s.Operation.OperationID, s.Operation.SchemaID, 1
	s.Binding.TenantID, s.Binding.UserID, s.Binding.RecordID = expected.Account.TenantID, "", ""
	s.Binding.AnonymousFlowID = "original-flow"
	s.Binding.ActorKind, s.Binding.ActorID = authorization.SubjectServiceAccount, "signin-service"
	var err error
	s.Fields, err = OAuthSigninAccountFields(expected)
	if err != nil {
		t.Fatal("original provider snapshot", err)
	}
	c, err := identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal("original anonymous callback", err)
	}
	return s, c
}

func TestOAuthSigninAccountSnapshotIsExactAndOwned(t *testing.T) {
	expected := signinAccountFixture()
	s, command := signinAccountCommand(t, expected)
	got, err := OAuthSigninAccount(command)
	if err != nil || got != expected {
		t.Fatal("original provider identity lost", err)
	}
	for _, original := range s.Fields {
		for _, mode := range []string{"missing", "wrong-kind", "changed"} {
			t.Run(original.Name+"/"+mode, func(t *testing.T) {
				changed := s
				changed.Fields = append([]identity.FeatureField(nil), s.Fields...)
				for i := range changed.Fields {
					if changed.Fields[i].Name != original.Name {
						continue
					}
					switch mode {
					case "missing":
						changed.Fields = append(changed.Fields[:i], changed.Fields[i+1:]...)
					case "wrong-kind":
						changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}
					case "changed":
						if original.Value.Kind == identity.FeatureText {
							changed.Fields[i].Value.Text = "other"
						} else {
							changed.Fields[i].Value.Uint64++
						}
					}
					break
				}
				candidate, e := identity.NewFeaturePreAuthCommand(changed, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				if e != nil {
					t.Fatal("changed command shape", e)
				}
				actual, e := OAuthSigninAccount(candidate)
				if mode == "changed" {
					if e == nil && actual == expected {
						t.Fatal("changed snapshot reconstructed original authority")
					}
				} else if e == nil {
					t.Fatal("incomplete or mistyped provider snapshot admitted")
				}
			})
		}
	}
	for _, mode := range []string{"metadata-only", "session-custody", "foreign-operation", "foreign-schema", "user-scoped", "human-actor", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			changed := s
			changed.Fields = append([]identity.FeatureField(nil), s.Fields...)
			var candidate identity.Command
			var err error
			bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			switch mode {
			case "metadata-only":
				candidate, err = identity.NewFeatureCommand(changed)
			case "session-custody":
				candidate, err = identity.NewFeatureSessionCommand(changed, bearer)
			default:
				switch mode {
				case "foreign-operation":
					changed.Operation.OperationID, changed.Binding.OperationID = "identity.oauth.other", "identity.oauth.other"
				case "foreign-schema":
					changed.Operation.SchemaID, changed.Binding.SchemaID = "other", "other"
				case "user-scoped":
					changed.Operation.SubjectRequirement, changed.Binding.UserID, changed.Binding.AnonymousFlowID = identity.FeatureSubjectUser, "selected-user", ""
				case "human-actor":
					changed.Binding.ActorKind = authorization.SubjectUser
				case "unknown-field":
					changed.Fields = append(changed.Fields, identity.FeatureField{Name: "oauth.signin.account.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
				}
				candidate, err = identity.NewFeaturePreAuthCommand(changed, bearer)
			}
			if err != nil {
				t.Fatal("negative fixture", err)
			}
			if _, err := OAuthSigninAccount(candidate); err == nil {
				t.Fatal("foreign callback/custody admitted")
			}
		})
	}
}

func TestOAuthSigninAccountRejectsInvalidSnapshot(t *testing.T) {
	for _, mode := range []string{"zero", "foreign-credential", "non-provider", "foreign-owner", "zero-account-version", "zero-link", "zero-user-epoch", "zero-identifier-epoch", "zero-credential-epoch"} {
		expected := signinAccountFixture()
		switch mode {
		case "zero":
			expected = ProviderAccountAdmission{}
		case "foreign-credential":
			expected.Credential.Credential.UserID = "other"
		case "non-provider":
			expected.Credential.Credential.Kind = identity.CredentialPassword
		case "foreign-owner":
			expected.Credential.Credential.Owner = "other"
		case "zero-account-version":
			expected.Account.Version = 0
		case "zero-link":
			expected.SocialLinkVersion = 0
		case "zero-user-epoch":
			expected.Credential.UserAuthorityVersion = 0
		case "zero-identifier-epoch":
			expected.Credential.IdentifierAuthorityVersion = 0
		case "zero-credential-epoch":
			expected.Credential.CredentialAuthorityVersion = 0
		}
		if fields, err := OAuthSigninAccountFields(expected); err == nil || fields != nil {
			t.Fatal("invalid provider snapshot admitted", mode)
		}
	}
}

func TestOAuthSigninAccountRequiresOriginalLiveApply(t *testing.T) {
	for _, mode := range []string{"zero-work", "nil-context", "cancelled", "foreign-owner", "reconstructed", "final-reconstructed", "wrong-descriptor", "returned", "admission-only"} {
		t.Run(mode, func(t *testing.T) {
			s, command := signinAccountCommand(t, signinAccountFixture())
			owner := &oauthSigninAccountParticipant{}
			_, _, plan := featurePlanFixture(t)
			plan.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: s.Operation}
			plan.Lifecycle = &LifecyclePlan{EventType: "oauth.signin.v1"}
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
				participant = &oauthSigninAccountParticipant{}
			case "reconstructed":
				candidate, _ = identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			case "final-reconstructed":
				candidate, _ = identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
			case "wrong-descriptor":
				plan.Feature.Contributor.ContractID = "other"
			case "returned":
				w.state.featureInvocation = nil
			case "admission-only":
				w.state.featureApplying = false
			}
			before := time.Time{}
			if w.state != nil {
				before, _ = w.state.ctx.Deadline()
			}
			if now, err := w.RequireOAuthSigninProviderAccount(ctx, participant, candidate); err == nil || !now.IsZero() {
				t.Fatal("unowned provider authority admitted")
			}
			if w.state != nil {
				after, _ := w.state.ctx.Deadline()
				if w.state.sqlStarted || w.state.failed == nil || w.state.binding != s.Binding || before != after {
					t.Fatal("invalid admission reached SQL, retargeted or remained usable")
				}
			}
		})
	}
}
