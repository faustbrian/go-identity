package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func groupFailureOperation(id string) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "scim", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if id == "identity.scim.group-patch" {
		op.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
	}
	return op
}

func TestGroupFeatureFailureRetainsOriginalClosedGroupDenials(t *testing.T) {
	for _, id := range []string{"identity.scim.group-create", "identity.scim.group-replace", "identity.scim.group-patch", "identity.scim.group-delete"} {
		t.Run(id, func(t *testing.T) {
			op := groupFailureOperation(id)
			w, participant, command := featureFailureOperationWork(t, op)
			w.state.subjectType = "scim_group"
			err := w.DenyFeature(context.Background(), participant, command, FeatureFailurePrecondition)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || w.state.featureFailure != FeatureFailurePrecondition {
				t.Fatal("original Group precondition denial was not retained", err)
			}
			q, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			result := featureOutcome(w.state.binding, &op, identity.CommitOutcomeNotCommitted, 0)
			wire, err := encodeJournalResultFailure(q, result, FeatureFailurePrecondition, "conflict")
			if err != nil {
				t.Fatal("original Group denial could not enter the existing result", err)
			}
			restored, code, err := decodeJournalResultFailure(q, wire, "conflict")
			if err != nil || code != FeatureFailurePrecondition || restored.Binding != result.Binding || restored.Feature.Operation != op {
				t.Fatal("original Group denial changed during recovery", err)
			}
		})
	}
}

func TestGroupFeatureFailureCannotBorrowAUserSubjectOrAnotherSchema(t *testing.T) {
	for _, mode := range []string{"user-subject", "future-schema", "wrong-owner", "wrong-patch-policy"} {
		t.Run(mode, func(t *testing.T) {
			op := groupFailureOperation("identity.scim.group-patch")
			w, participant, command := featureFailureOperationWork(t, op)
			w.state.subjectType = "scim_group"
			switch mode {
			case "user-subject":
				w.state.subjectType = "scim_user"
			case "future-schema":
				w.state.feature.Operation.SchemaVersion++
			case "wrong-owner":
				w.state.feature.Operation.Owner = "another"
			case "wrong-patch-policy":
				w.state.feature.Operation.VersionPolicy = identity.FeatureVersionSequential
			}
			if err := w.DenyFeature(context.Background(), participant, command, FeatureFailurePrecondition); err == nil || w.state.featureFailure != 0 {
				t.Fatal("foreign Group tuple retained denial detail", err)
			}
		})
	}
}

func TestGroupInvalidMemberFailureIsLimitedToMemberWritingOperations(t *testing.T) {
	for _, id := range []string{"identity.scim.group-create", "identity.scim.group-replace", "identity.scim.group-patch", "identity.scim.group-delete", "identity.scim.user-patch"} {
		t.Run(id, func(t *testing.T) {
			op := groupFailureOperation(id)
			if id == "identity.scim.user-patch" {
				op = scimUserUpdateOperation(id)
			}
			w, participant, command := featureFailureOperationWork(t, op)
			w.state.subjectType = "scim_group"
			allowed := id != "identity.scim.group-delete" && id != "identity.scim.user-patch"
			if id == "identity.scim.user-patch" {
				w.state.subjectType = "scim_user"
			}
			// Value 4 is the additive wire code; values 1..3 remain unchanged.
			code := FeatureFailureCode(4)
			_ = w.DenyFeature(context.Background(), participant, command, code)
			if !allowed {
				if w.state.featureFailure != 0 {
					t.Fatal("invalid-member detail escaped a Group member-writing operation")
				}
				return
			}
			if w.state.featureFailure != code {
				t.Fatal("Group member denial was not retained")
			}
			q, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			result := featureOutcome(w.state.binding, &op, identity.CommitOutcomeNotCommitted, 0)
			wire, err := encodeJournalResultFailure(q, result, code, "conflict")
			if err != nil {
				t.Fatal("member denial missing from original result", err)
			}
			if _, got, err := decodeJournalResultFailure(q, wire, "conflict"); err != nil || got != code {
				t.Fatal("original member denial did not recover", err)
			}
		})
	}
}
