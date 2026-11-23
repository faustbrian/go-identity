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

type ssoOAuth2GrantFactorFixture struct {
	command identity.FeatureCommandSpec
	binding identity.CommandBinding
	feature kernel.FeatureRegistration
	life    kernel.LifecyclePlan
	record  session.SessionSpec
}

func ssoOAuth2GrantFactorScopeFixture(t *testing.T) ssoOAuth2GrantFactorFixture {
	t.Helper()
	record, err := ssoOAuth2FactorSession(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	operation := identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.provider-token.revoke",
		SchemaID: "identity.sso.provider-token.revoke.native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser,
	}
	binding := identity.CommandBinding{
		CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a",
		ActorID: "user-a", ActorKind: authorization.SubjectUser,
		OperationID: operation.OperationID, SchemaID: operation.SchemaID, SchemaVersion: 1,
		RecordID: "AgICAgICAgICAgICAgICAg", PolicyID: "grant-revoke", PolicyVersion: 1,
		CorrelationID: "grant-revoke-correlation",
	}
	return ssoOAuth2GrantFactorFixture{
		command: identity.FeatureCommandSpec{Operation: operation, Binding: binding, Fields: []identity.FeatureField{
			{Name: "sso.vault.session-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: record.SessionID}},
			{Name: "sso.vault.session-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: record.Version}},
		}},
		binding: binding,
		feature: kernel.FeatureRegistration{Operation: operation, Contributor: kernel.ContributorDescriptor{
			Owner: "sso/postgres", ContractID: "sso.enterprise-token-vault", Version: 1,
		}},
		life:   kernel.LifecyclePlan{EventType: "enterprise_provider.token_revocation_settled.v1", AfterVersion: 1},
		record: record,
	}
}

func TestSSOOAuth2GrantRevocationFactorScopeAcceptsExactOriginalSession(t *testing.T) {
	input := ssoOAuth2GrantFactorScopeFixture(t)
	if _, err := identity.NewFeatureCommand(input.command); err != nil {
		t.Fatal("grant revocation fixture is not a valid command", err)
	}
	if err := ssoOAuth2GrantRevocationFactorScope(input.command, input.binding, input.feature, input.life, input.record); err != nil {
		t.Fatal("exact grant revocation factor scope denied", err)
	}
	input.command.Fields[0], input.command.Fields[1] = input.command.Fields[1], input.command.Fields[0]
	input.command.Fields = append(input.command.Fields, identity.FeatureField{
		Name: "sso.vault.provider-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "provider-a"},
	})
	if err := ssoOAuth2GrantRevocationFactorScope(input.command, input.binding, input.feature, input.life, input.record); err != nil {
		t.Fatal("field ordering or another owner-owned field changed exact session scope", err)
	}
}

func TestSSOOAuth2GrantRevocationFactorScopeRejectsForeignScope(t *testing.T) {
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
		"sibling operation": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation.OperationID = "identity.sso.provider-token.refresh"
			f.binding.OperationID = f.command.Operation.OperationID
		},
		"session revoke operation": func(f *ssoOAuth2GrantFactorFixture) {
			f.command.Operation = session.RevokeOneOperation()
			f.binding.OperationID, f.binding.SchemaID = f.command.Operation.OperationID, f.command.Operation.SchemaID
		},
		"schema": func(f *ssoOAuth2GrantFactorFixture) {
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
		"contributor owner":         func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.Owner = "identity/oauth/postgres" },
		"contributor contract":      func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.ContractID += ".alias" },
		"contributor version":       func(f *ssoOAuth2GrantFactorFixture) { f.feature.Contributor.Version = 2 },
		"lifecycle event":           func(f *ssoOAuth2GrantFactorFixture) { f.life.EventType = "enterprise_provider.token_refreshed.v1" },
		"lifecycle index":           func(f *ssoOAuth2GrantFactorFixture) { f.life.EventIndex = 1 },
		"lifecycle before":          func(f *ssoOAuth2GrantFactorFixture) { f.life.BeforeVersion = 1 },
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
		"sibling session":            func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[0].Value.Text = "sibling-session" },
		"changed session generation": func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[1].Value.Uint64++ },
		"zero session generation":    func(f *ssoOAuth2GrantFactorFixture) { f.command.Fields[1].Value.Uint64 = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			input := ssoOAuth2GrantFactorScopeFixture(t)
			mutate(&input)
			input.command.Binding = input.binding
			input.feature.Operation = input.command.Operation
			if err := ssoOAuth2GrantRevocationFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
				t.Fatal("foreign grant revocation factor scope admitted")
			}
		})
	}
}

func TestSSOOAuth2GrantRevocationFactorScopeRequiresUnchangedWorkBinding(t *testing.T) {
	input := ssoOAuth2GrantFactorScopeFixture(t)
	input.binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	if err := ssoOAuth2GrantRevocationFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
		t.Fatal("substituted Work command binding admitted")
	}
	input = ssoOAuth2GrantFactorScopeFixture(t)
	input.feature.Operation.SchemaID += ".substituted"
	if err := ssoOAuth2GrantRevocationFactorScope(input.command, input.binding, input.feature, input.life, input.record); err == nil {
		t.Fatal("substituted Work feature operation admitted")
	}
}

func TestRequireSSOOAuth2GrantRevocationFactorsRejectsUnownedInvocation(t *testing.T) {
	input := ssoOAuth2GrantFactorScopeFixture(t)
	command, err := identity.NewFeatureCommand(input.command)
	if err != nil {
		t.Fatal(err)
	}
	record := ssoOAuth2FactorSession(t)
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := RequireSSOOAuth2GrantRevocationFactors(ctx, kernel.Work{}, nil, command, record); err == nil {
			t.Fatal("unowned grant invocation borrowed factor authority")
		}
	}
	if err := RequireSSOOAuth2GrantRevocationFactors(t.Context(), kernel.Work{}, nil, identity.Command{}, record); err == nil {
		t.Fatal("missing grant command borrowed factor authority")
	}
	if err := RequireSSOOAuth2GrantRevocationFactors(t.Context(), kernel.Work{}, nil, command, session.Session{}); err == nil {
		t.Fatal("missing session borrowed factor authority")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequireSSOOAuth2GrantRevocationFactors(ctx, kernel.Work{}, nil, command, record); !errors.Is(err, context.Canceled) {
		t.Fatal("grant factor guard lost cancellation", err)
	}
}
