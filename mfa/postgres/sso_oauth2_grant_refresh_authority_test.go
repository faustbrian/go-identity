package mfapostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func ssoOAuth2GrantRefreshFactorScopeFixture(t *testing.T) ssoOAuth2GrantFactorFixture {
	t.Helper()
	input := ssoOAuth2GrantFactorScopeFixture(t)
	input.command.Operation.OperationID = "identity.sso.provider-token.refresh"
	input.command.Operation.SchemaID = "identity.sso.provider-token.refresh.native-v1"
	input.binding.OperationID = input.command.Operation.OperationID
	input.binding.SchemaID = input.command.Operation.SchemaID
	input.binding.PolicyID = "grant-refresh"
	input.binding.CorrelationID = "grant-refresh-correlation"
	input.command.Binding = input.binding
	input.feature.Operation = input.command.Operation
	input.life.EventType = "enterprise_provider.token_refresh_settled.v1"
	return input
}

func TestSSOOAuth2GrantRefreshFactorScopeAcceptsExactOriginalSession(t *testing.T) {
	input := ssoOAuth2GrantRefreshFactorScopeFixture(t)
	if _, err := identity.NewFeatureCommand(input.command); err != nil {
		t.Fatal("grant refresh fixture is not a valid command", err)
	}
	if err := ssoOAuth2GrantRefreshFactorScope(input.command, input.binding, input.feature, input.life, input.record); err != nil {
		t.Fatal("exact grant refresh factor scope denied", err)
	}
	input.command.Fields[0], input.command.Fields[1] = input.command.Fields[1], input.command.Fields[0]
	input.command.Fields = append(input.command.Fields, identity.FeatureField{
		Name: "sso.vault.provider-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "provider-a"},
	})
	if err := ssoOAuth2GrantRefreshFactorScope(input.command, input.binding, input.feature, input.life, input.record); err != nil {
		t.Fatal("field ordering or another owner-owned field changed exact session scope", err)
	}
}

func TestSSOOAuth2GrantRefreshFactorScopeRejectsForeignScope(t *testing.T) {
	for name, mutate := range map[string]func(*ssoOAuth2GrantFactorFixture){
		"tenant":                      func(f *ssoOAuth2GrantFactorFixture) { f.binding.TenantID = "other-tenant" },
		"user":                        func(f *ssoOAuth2GrantFactorFixture) { f.binding.UserID, f.binding.ActorID = "other-user", "other-user" },
		"actor":                       func(f *ssoOAuth2GrantFactorFixture) { f.binding.ActorID = "other-user" },
		"service actor":               func(f *ssoOAuth2GrantFactorFixture) { f.binding.ActorKind = authorization.SubjectServiceAccount },
		"anonymous flow":              func(f *ssoOAuth2GrantFactorFixture) { f.binding.AnonymousFlowID = "other-flow" },
		"empty grant callback":        func(f *ssoOAuth2GrantFactorFixture) { f.binding.RecordID = "" },
		"noncanonical grant callback": func(f *ssoOAuth2GrantFactorFixture) { f.binding.RecordID += "==" },
		"zero grant callback":         func(f *ssoOAuth2GrantFactorFixture) { f.binding.RecordID = "AAAAAAAAAAAAAAAAAAAAAA" },
		"operation owner":             func(f *ssoOAuth2GrantFactorFixture) { f.command.Operation.Owner = "identity/oauth" },
		"sibling revoke operation": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.OperationID = "identity.sso.provider-token.revoke"
			f.command.Operation.SchemaID = "identity.sso.provider-token.revoke.native-v1"
			f.binding.OperationID, f.binding.SchemaID = f.command.Operation.OperationID, f.command.Operation.SchemaID
		},
		"session revoke operation": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation = session.RevokeOneOperation()
			f.binding.OperationID, f.binding.SchemaID = f.command.Operation.OperationID, f.command.Operation.SchemaID
		},
		"schema alias": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.SchemaID += ".alias"
			f.binding.SchemaID = f.command.Operation.SchemaID
		},
		"schema version": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.SchemaVersion, f.binding.SchemaVersion = 2, 2
		},
		"record requirement": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.RecordRequirement = identity.FeatureRecordOmitted
		},
		"anonymous subject": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
		"version policy": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
		},
		"contributor owner":    func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.Owner = "identity/oauth/postgres" },
		"contributor contract": func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.ContractID += ".alias" },
		"contributor version":  func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.Version = 2 },
		"lifecycle event":      func(f *ssoOAuth2GrantFactorFixture) { f.life.EventType = "enterprise_provider.token_refreshed.v1" },
		"revoke lifecycle": func(f *ssoOAuth2GrantFactorFixture) {
			f.life.EventType = "enterprise_provider.token_revocation_settled.v1"
		},
		"lifecycle index":           func(f *ssoOAuth2GrantFactorFixture) { f.life.EventIndex = 1 },
		"lifecycle before":          func(f *ssoOAuth2GrantFactorFixture) { f.life.BeforeVersion = 1 },
		"token version lifecycle":   func(f *ssoOAuth2GrantFactorFixture) { f.life.BeforeVersion, f.life.AfterVersion = 1, 2 },
		"lifecycle after":           func(f *ssoOAuth2GrantFactorFixture) { f.life.AfterVersion = 2 },
		"missing session id":        func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields = f.command.Fields[1:] },
		"missing session version":   func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields = f.command.Fields[:1] },
		"duplicate session id":      func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields = append(f.command.Fields, f.command.Fields[0]) },
		"duplicate session version": func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields = append(f.command.Fields, f.command.Fields[1]) },
		"session id kind": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}
		},
		"session version kind": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Fields[1].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "1"}
		},
		"session field alias":        func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[0].Name += ".alias" },
		"sibling session":            func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[0].Value.Text = "sibling-session" },
		"changed session generation": func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[1].Value.Uint64++ },
		"zero session generation":    func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[1].Value.Uint64 = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			input := ssoOAuth2GrantRefreshFactorScopeFixture(t)
			mutate(&input)
			input.command.Binding = input.binding
			input.feature.Operation = input.command.Operation
			if err := ssoOAuth2GrantRefreshFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
				t.Fatal("foreign grant refresh factor scope admitted")
			}
		})
	}
}

func TestSSOOAuth2GrantRefreshFactorScopeRequiresUnchangedWorkBinding(t *testing.T) {
	input := ssoOAuth2GrantRefreshFactorScopeFixture(t)
	input.binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	if err := ssoOAuth2GrantRefreshFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
		t.Fatal("substituted Work command binding admitted")
	}
	input = ssoOAuth2GrantRefreshFactorScopeFixture(t)
	input.feature.Operation.SchemaID += ".substituted"
	if err := ssoOAuth2GrantRefreshFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
		t.Fatal("substituted Work feature operation admitted")
	}
}

func TestRequireSSOOAuth2GrantRefreshFactorsRejectsUnownedInvocation(t *testing.T) {
	input := ssoOAuth2GrantRefreshFactorScopeFixture(t)
	command, err := identity.NewFeatureCommand(input.command)
	if err != nil {
		t.Fatal(err)
	}
	record := ssoOAuth2FactorSession(t)
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := RequireSSOOAuth2GrantRefreshFactors(ctx, kernel.Work{}, nil, command, record); err == nil {
			t.Fatal("unowned grant refresh invocation borrowed factor authority")
		}
	}
	if err := RequireSSOOAuth2GrantRefreshFactors(t.Context(), kernel.Work{}, nil, identity.Command{}, record); err == nil {
		t.Fatal("missing grant command borrowed factor authority")
	}
	if err := RequireSSOOAuth2GrantRefreshFactors(t.Context(), kernel.Work{}, nil, command, session.Session{}); err == nil {
		t.Fatal("missing session borrowed factor authority")
	}
	if err := RequireSSOOAuth2GrantRefreshFactors(t.Context(), kernel.Work{}, nil, command, ssoOIDCFactorSession(t)); err == nil {
		t.Fatal("OIDC session borrowed OAuth2 factor authority")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequireSSOOAuth2GrantRefreshFactors(ctx, kernel.Work{}, nil, command, record); !errors.Is(err, context.Canceled) {
		t.Fatal("grant refresh factor guard lost cancellation", err)
	}
}
