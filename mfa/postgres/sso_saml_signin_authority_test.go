package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// This owner is deliberately never registered. No contributor callback may
// substitute for the coordinator's invocation custody.
type unownedSAMLFactorContributor struct{}

func (*unownedSAMLFactorContributor) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-login-callback", Version: 1}
}

func (*unownedSAMLFactorContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLSigninOperation()}
}

func (*unownedSAMLFactorContributor) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	panic("unowned SAML recovery invoked")
}

func (*unownedSAMLFactorContributor) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	panic("unowned SAML command validation invoked")
}

func (*unownedSAMLFactorContributor) ApplyFeature(context.Context, kernel.Work, identity.Command) (identity.FeatureReceipt, error) {
	panic("unowned SAML mutation invoked")
}

func samlFactorCommandFixture(t *testing.T) (identity.FeatureCommandSpec, identity.Command) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	account := kernel.ProviderAccountAdmission{
		Account:           identity.Account{ID: "account-a", TenantID: "tenant-a", UserID: "selected-user", Provider: "sso.saml.v1." + strings.Repeat("a", 64), Issuer: "urn:example:saml-idp", Subject: "subject-a", Version: 5},
		SocialLinkVersion: 7,
		Credential:        kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-ref", TenantID: "tenant-a", UserID: "selected-user", Kind: identity.CredentialProvider, Owner: "sso", Version: 11}, UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19},
	}
	fields, err := kernel.SSOSAMLSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	op := kernel.SSOSAMLSigninOperation()
	spec := identity.FeatureCommandSpec{Operation: op, Binding: identity.CommandBinding{
		CommandID: id, TenantID: "tenant-a", AnonymousFlowID: "original-flow", ActorID: "signin-service", ActorKind: authorization.SubjectServiceAccount,
		RecordID: string(start), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		PolicyID: "signin", PolicyVersion: 1, CorrelationID: string(id),
	}, Fields: fields}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	command, err := identity.NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kernel.SSOSAMLSigninAccount(command); err != nil || got != account {
		t.Fatal("original SAML account fixture lost selected identity", err)
	}
	return spec, command
}

func TestSSOSAMLSigninFactorsRequirePrimaryAndOwnedInvocation(t *testing.T) {
	_, command := samlFactorCommandFixture(t)
	owner := &unownedSAMLFactorContributor{}
	for _, ctx := range []context.Context{nil, t.Context()} {
		if state, err := ReadSSOSAMLSigninFactors(ctx, nil, "tenant-a", "selected-user", time.Second); err == nil || state.Version() != 0 {
			t.Fatal("missing primary supplied factor metadata")
		}
		for _, candidate := range []kernel.FeatureExecutionContributor{nil, owner} {
			if state, err := RequireSSOSAMLSigninFactors(ctx, kernel.Work{}, candidate, command, 1); err == nil || state.Version() != 0 {
				t.Fatal("unowned SAML callback supplied factor authority")
			}
		}
	}
	if state, err := RequireSSOSAMLSigninFactors(t.Context(), kernel.Work{}, owner, command, 0); err == nil || state.Version() != 0 {
		t.Fatal("zero expected generation supplied factor authority")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if state, err := RequireSSOSAMLSigninFactors(ctx, kernel.Work{}, owner, command, 1); !errors.Is(err, context.Canceled) || state.Version() != 0 {
		t.Fatal("cancelled invocation lost cancellation or supplied factor authority", err)
	}
}

func TestSSOSAMLSigninFactorsRejectForeignAndMissingCommandsBeforeStorage(t *testing.T) {
	spec, original := samlFactorCommandFixture(t)
	cookie, _ := original.PreAuthCookie()
	owner := &unownedSAMLFactorContributor{}
	for _, mode := range []string{"missing-command", "missing-custody", "missing-account", "oauth2", "oidc", "saml-logout"} {
		t.Run(mode, func(t *testing.T) {
			candidate := spec
			command := identity.Command{}
			var err error
			switch mode {
			case "missing-command":
			case "missing-custody":
				command, err = identity.NewFeatureCommand(candidate)
			default:
				switch mode {
				case "missing-account":
					candidate.Fields = nil
				case "oauth2":
					candidate.Operation = kernel.SSOOAuth2SigninOperation()
				case "oidc":
					candidate.Operation = identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
				case "saml-logout":
					candidate.Operation.OperationID, candidate.Operation.SchemaID = "identity.sso.saml-slo", "sso-saml-slo-v1"
				}
				candidate.Binding.OperationID, candidate.Binding.SchemaID = candidate.Operation.OperationID, candidate.Operation.SchemaID
				command, err = identity.NewFeaturePreAuthCommand(candidate, cookie)
			}
			if err != nil {
				t.Fatal("rejection fixture", err)
			}
			if state, err := RequireSSOSAMLSigninFactors(t.Context(), kernel.Work{}, owner, command, 1); err == nil || state.Version() != 0 {
				t.Fatal("foreign or incomplete invocation supplied factor authority")
			}
		})
	}
}
