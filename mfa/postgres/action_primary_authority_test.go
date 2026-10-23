package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func actionFactorFixture(t *testing.T, transfer bool) (identity.FeatureCommandSpec, kernel.FeatureRegistration) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username.update", SchemaID: "identity.username.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	owner := kernel.ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}
	user := identity.UserID("z-user")
	if transfer {
		op = identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.owner-transfer", SchemaID: "organization-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		owner = kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
		user = "a-user"
	}
	s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: user, ActorKind: authorization.SubjectUser, ActorID: "z-user", RecordID: "record", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id)}, Operation: op, Fields: []identity.FeatureField{
		{Name: "action-primary.actor-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}},
		{Name: "action-primary.target-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}},
	}}
	if transfer {
		s.Fields[1].Value.Uint64 = 9
	}
	return s, kernel.FeatureRegistration{Contributor: owner, Operation: op}
}

func TestActionPrimaryFactorScopeRequiresOriginalVersionsAndClosedOwner(t *testing.T) {
	for _, transfer := range []bool{false, true} {
		s, registration := actionFactorFixture(t, transfer)
		target := uint64(7)
		if transfer {
			target = 9
		}
		subjects, err := actionPrimaryFactorSubjects(s, registration, 7, target)
		if err != nil {
			t.Fatal("valid selected factor scope denied", err)
		}
		if transfer {
			if len(subjects) != 2 || subjects[0].user != "a-user" || subjects[0].version != 9 || subjects[1].user != "z-user" || subjects[1].version != 7 {
				t.Fatal("distinct subjects lost original versions or canonical lock order")
			}
		} else if len(subjects) != 1 || subjects[0].user != "z-user" || subjects[0].version != 7 {
			t.Fatal("self scope duplicated or substituted subject")
		}
		for _, mode := range []string{"missing", "changed-actor", "changed-target", "duplicate", "unknown", "kind", "service", "scope", "owner", "schema", "operation", "zero"} {
			request, reg := s, registration
			request.Fields = append([]identity.FeatureField(nil), s.Fields...)
			actorVersion := uint64(7)
			switch mode {
			case "missing":
				request.Fields = request.Fields[:1]
			case "changed-actor":
				request.Fields[0].Value.Uint64++
			case "changed-target":
				request.Fields[1].Value.Uint64++
			case "duplicate":
				request.Fields = append(request.Fields, request.Fields[0])
			case "unknown":
				request.Fields = append(request.Fields, identity.FeatureField{Name: "action-primary.unrecognized", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}})
			case "kind":
				request.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "7"}
			case "service":
				request.Binding.ActorKind = authorization.SubjectServiceAccount
			case "scope":
				if transfer {
					request.Binding.UserID = identity.UserID(request.Binding.ActorID)
				} else {
					request.Binding.UserID = "foreign"
				}
			case "owner":
				reg.Contributor.Owner = "foreign/postgres"
			case "schema":
				request.Operation.SchemaVersion++
			case "operation":
				request.Operation.OperationID = "identity.email.address-remove"
			case "zero":
				actorVersion = 0
			}
			if _, err := actionPrimaryFactorSubjects(request, reg, actorVersion, target); err == nil {
				t.Fatal("substituted factor scope admitted", mode)
			}
		}
	}
	if err := RequireActionPrimaryFactors(context.Background(), kernel.Work{}, nil, identity.Command{}, 1, 1); err == nil {
		t.Fatal("factor read escaped actual protected invocation")
	}
}

func TestPasskeyEnrollmentFactorScopeKeepsExactNativeOwner(t *testing.T) {
	testPasskeyActionFactorScope(t, []string{"identity.passkey.register-options", "identity.passkey.register-verify"})
}

func TestPasskeyUpdateFactorScopeKeepsExactNativeOwner(t *testing.T) {
	testPasskeyActionFactorScope(t, []string{"identity.passkey.update"})
}

func testPasskeyActionFactorScope(t *testing.T, actions []string) {
	t.Helper()
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			s, registration := actionFactorFixture(t, false)
			s.Operation = identity.FeatureOperation{Owner: "passkey", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			s.Binding.OperationID, s.Binding.SchemaID = action, s.Operation.SchemaID
			registration = kernel.FeatureRegistration{Operation: s.Operation, Contributor: kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}}
			subjects, err := actionPrimaryFactorSubjects(s, registration, 7, 7)
			if err != nil || len(subjects) != 1 || subjects[0].user != s.Binding.UserID || subjects[0].version != 7 {
				t.Fatal("native self-only passkey action lost its original factor scope", err)
			}
			for _, mode := range []string{"foreign-subject", "foreign-owner", "wrong-schema", "missing-field", "changed-generation", "unselected-action"} {
				request, owner := s, registration
				request.Fields = append([]identity.FeatureField(nil), s.Fields...)
				switch mode {
				case "foreign-subject":
					request.Binding.UserID = "foreign"
				case "foreign-owner":
					owner.Contributor.Owner = "identity/username/postgres"
				case "wrong-schema":
					request.Operation.SchemaID = "mfa-enrollment"
				case "missing-field":
					request.Fields = request.Fields[:1]
				case "changed-generation":
					request.Fields[1].Value.Uint64++
				case "unselected-action":
					request.Operation.OperationID = "identity.passkey.delete"
					request.Operation.SchemaID = request.Operation.OperationID + ".native-v1"
					request.Binding.OperationID, request.Binding.SchemaID = request.Operation.OperationID, request.Operation.SchemaID
					owner.Operation = request.Operation
				}
				if _, err := actionPrimaryFactorSubjects(request, owner, 7, 7); err == nil {
					t.Fatal("passkey action accepted substituted factor custody", mode)
				}
			}
		})
	}
}
