package mfapostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestAdminSessionRevokeActorTOTPBindingAdmitsOnlyExactActorAndOperation(t *testing.T) {
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	registration := kernel.FeatureRegistration{
		Operation: identity.FeatureOperation{
			Owner: "identity/session", OperationID: "identity.admin.session-revoke",
			SchemaID: "session-admin-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
		},
		Contributor: kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1},
	}
	binding := identity.CommandBinding{
		CommandID: commandID, TenantID: "tenant", UserID: "target", ActorID: "administrator",
		ActorKind: authorization.SubjectUser, RecordID: "target-session",
		OperationID: registration.Operation.OperationID, SchemaID: registration.Operation.SchemaID,
		SchemaVersion: 1, PolicyID: "administrator-policy", PolicyVersion: 1, CorrelationID: string(commandID),
	}
	for _, tc := range []struct {
		name  string
		actor identity.UserID
		alter func(*identity.CommandBinding, *kernel.FeatureRegistration)
		want  bool
	}{
		{name: "exact administrator across target", actor: "administrator", want: true},
		{name: "administrator is target", actor: "administrator", want: true, alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "administrator" }},
		{name: "empty actor"},
		{name: "target factor", actor: "target"},
		{name: "foreign actor", actor: "foreign"},
		{name: "wrong command actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.ActorID = "foreign" }},
		{name: "service actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.ActorKind = authorization.SubjectServiceAccount
		}},
		{name: "API key actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.ActorKind = authorization.SubjectAPIKey
		}},
		{name: "missing actor kind", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.ActorKind = "" }},
		{name: "other owner", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.Owner = "identity/impersonation"
		}},
		{name: "other contributor", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Contributor.Owner = "identity/impersonation/postgres"
		}},
		{name: "other contract", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Contributor.ContractID = "identity.session"
		}},
		{name: "other contributor version", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) { f.Contributor.Version = 2 }},
		{name: "self-service revoke", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.OperationID, f.Operation.OperationID = "identity.session.revoke-one", "identity.session.revoke-one"
			b.SchemaID, f.Operation.SchemaID = "session-revoke-one", "session-revoke-one"
		}},
		{name: "impersonation revoke", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.OperationID, f.Operation.OperationID = "identity.impersonation.revoke", "identity.impersonation.revoke"
		}},
		{name: "other binding operation", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.OperationID = "identity.session.revoke-one"
		}},
		{name: "other registered operation", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.OperationID = "identity.session.revoke-one"
		}},
		{name: "other schema", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.SchemaID, f.Operation.SchemaID = "session-revoke-one", "session-revoke-one"
		}},
		{name: "other binding schema", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.SchemaID = "session-revoke-one" }},
		{name: "other schema version", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.SchemaVersion, f.Operation.SchemaVersion = 2, 2
		}},
		{name: "omitted record registration", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.RecordRequirement = identity.FeatureRecordOmitted
		}},
		{name: "anonymous target registration", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		}},
		{name: "other version policy", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
		}},
		{name: "missing tenant", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.TenantID = "" }},
		{name: "invalid tenant", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.TenantID = "tenant foreign" }},
		{name: "missing target", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "" }},
		{name: "invalid target", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "target foreign" }},
		{name: "anonymous target", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.AnonymousFlowID = "anonymous" }},
		{name: "missing session", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.RecordID = "" }},
		{name: "invalid session", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.RecordID = "session foreign" }},
		{name: "missing command", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.CommandID = "" }},
		{name: "noncanonical command", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.CommandID = "command" }},
		{name: "missing policy", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.PolicyID = "" }},
		{name: "missing policy version", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.PolicyVersion = 0 }},
		{name: "missing correlation", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.CorrelationID = "" }},
		{name: "account link mode", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.LinkMode = identity.AccountLinkMode(1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f := binding, registration
			if tc.alter != nil {
				tc.alter(&b, &f)
			}
			if got := adminSessionRevokeActorTOTPBindingMatches(b, f, tc.actor); got != tc.want {
				t.Fatalf("admin session revoke actor factor admission = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRequireAdminSessionRevokeActorTOTPSessionFactorRejectsAbsentAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expected := TOTPSessionFactorState{EnrollmentVersion: 1, AuthorityVersion: 1}
	if err := RequireAdminSessionRevokeActorTOTPSessionFactor(ctx, kernel.Work{}, nil, "administrator", "factor", expected); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context = %v, want context cancellation", err)
	}
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		expected TOTPSessionFactorState
	}{
		{name: "nil context", expected: expected},
		{name: "missing enrollment version", ctx: context.Background(), expected: TOTPSessionFactorState{AuthorityVersion: 1}},
		{name: "missing authority version", ctx: context.Background(), expected: TOTPSessionFactorState{EnrollmentVersion: 1}},
		{name: "not live Work", ctx: context.Background(), expected: expected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireAdminSessionRevokeActorTOTPSessionFactor(tc.ctx, kernel.Work{}, nil, "administrator", "factor", tc.expected)
			var invalid identity.InvalidInputError
			if !errors.As(err, &invalid) || invalid.Field != "factor_authority" {
				t.Fatalf("absent authority = %v, want invalid factor authority", err)
			}
		})
	}
}
