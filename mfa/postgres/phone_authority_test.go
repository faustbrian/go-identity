package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func phoneFactorFixture(t *testing.T, operation string) (identity.FeatureCommandSpec, kernel.FeatureRegistration) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: operation, SchemaID: operation + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "user", ActorKind: authorization.SubjectUser, ActorID: "user", RecordID: "number", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id)}, Operation: op, Fields: []identity.FeatureField{
		{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}},
		{Name: "phone.recipient-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 3}},
	}}
	return s, kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
}

func TestPhoneFactorScopePreservesFrozenOriginalGeneration(t *testing.T) {
	for _, operation := range []string{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.remove"} {
		t.Run(operation, func(t *testing.T) {
			s, registration := phoneFactorFixture(t, operation)
			command, err := identity.NewFeatureCommand(s)
			if err != nil {
				t.Fatal(err)
			}
			// Mutation of either the construction input or an owned projection must
			// not replace the generation frozen into the original command.
			s.Fields[0].Value.Uint64 = 8
			projection, _ := command.Feature()
			projection.Fields[0].Value.Uint64 = 9
			user, err := phoneFactorSubject(command, s.Binding, registration, 7)
			if err != nil || user != "user" {
				t.Fatalf("original self-user generation denied: user=%q err=%v", user, err)
			}
			for _, replacement := range []uint64{0, 8, 9} {
				if _, err := phoneFactorSubject(command, s.Binding, registration, replacement); err == nil {
					t.Fatalf("unfrozen generation %d admitted", replacement)
				}
			}
		})
	}
}

func TestPhoneFactorScopeRejectsSubstitutedOwnerActionAndVersion(t *testing.T) {
	for _, operation := range []string{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.remove"} {
		for _, mode := range []string{"missing-version", "changed-version", "version-kind", "unknown-factor-field", "unknown-factor-suffix", "foreign-actor", "service-actor", "foreign-owner", "foreign-contract", "contract-version", "foreign-operation-owner", "other-action", "managed-schema", "schema-version", "record-omitted", "anonymous-subject", "invocation-tenant", "invocation-user", "invocation-record", "invocation-operation", "zero-command"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				s, registration := phoneFactorFixture(t, operation)
				switch mode {
				case "missing-version":
					s.Fields = s.Fields[1:]
				case "changed-version":
					s.Fields[0].Value.Uint64++
				case "version-kind":
					s.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "7"}
				case "unknown-factor-field":
					s.Fields = append(s.Fields, identity.FeatureField{Name: "phone.factor-current-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}})
				case "unknown-factor-suffix":
					s.Fields = append(s.Fields, identity.FeatureField{Name: "phone.factor-version.extra", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}})
				case "foreign-actor":
					s.Binding.ActorID = "another-user"
				case "service-actor":
					s.Binding.ActorKind = authorization.SubjectServiceAccount
				case "foreign-owner":
					registration.Contributor.Owner = "foreign/postgres"
				case "foreign-contract":
					registration.Contributor.ContractID = "identity.otp.store"
				case "contract-version":
					registration.Contributor.Version++
				case "foreign-operation-owner":
					s.Operation.Owner = "identity/otp"
				case "other-action":
					s.Operation.OperationID = "identity.phone.update"
					s.Operation.SchemaID = s.Operation.OperationID + ".native-v1"
					s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
				case "managed-schema":
					s.Operation.SchemaID = operation + ".managed-v1"
					s.Binding.SchemaID = s.Operation.SchemaID
				case "schema-version":
					s.Operation.SchemaVersion++
					s.Binding.SchemaVersion++
				case "record-omitted":
					s.Operation.RecordRequirement = identity.FeatureRecordOmitted
					s.Binding.RecordID = ""
				case "anonymous-subject":
					s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
					s.Binding.UserID, s.Binding.AnonymousFlowID = "", "flow"
				}
				if mode == "foreign-operation-owner" || mode == "other-action" || mode == "managed-schema" || mode == "schema-version" || mode == "record-omitted" || mode == "anonymous-subject" {
					registration.Operation = s.Operation
				}
				command, err := identity.NewFeatureCommand(s)
				if err != nil {
					t.Fatal("fixture must reach the MFA scope boundary", err)
				}
				binding := s.Binding
				switch mode {
				case "invocation-tenant":
					binding.TenantID = "foreign"
				case "invocation-user":
					binding.UserID = "foreign"
				case "invocation-record":
					binding.RecordID = "foreign"
				case "invocation-operation":
					registration.Operation.OperationID = "identity.phone.update"
				case "zero-command":
					command = identity.Command{}
				}
				if _, err := phoneFactorSubject(command, binding, registration, 7); err == nil {
					t.Fatal("substituted phone factor authority admitted")
				}
			})
		}
	}
}

func TestPhoneFactorReaderRejectsMissingPrimaryAndInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := ReadPhoneFactors(ctx, nil, "tenant", "user", time.Second); err == nil {
			t.Fatal("missing native primary inferred known-empty factors")
		}
		if _, err := RequirePhoneFactors(ctx, kernel.Work{}, nil, identity.Command{}, 7); err == nil {
			t.Fatal("absent protected invocation reached factor authority")
		}
	}
}
