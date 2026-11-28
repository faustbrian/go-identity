package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const impersonationApproverSetField = "impersonation.approver-set"

// ImpersonationApproverAdmission describes one original retained decision and
// the reviewer epochs the native impersonation owner must revalidate. It is
// not an authentication proof or a policy decision.
type ImpersonationApproverAdmission struct {
	ApprovalCommandID identity.CommandID
	User              identity.User
	Authorization     UserAuthorizationAdmission
}

// ImpersonationApproverSetField commits the complete original sequence of
// distinct reviewer decisions to a configurable impersonation Start command.
// The native owner supplies decisions in retained ordinal order; the field
// contains only their digest, not another approval record or credential.
func ImpersonationApproverSetField(b identity.CommandBinding, set []ImpersonationApproverAdmission) (identity.FeatureField, error) {
	op := impersonationStartOperation()
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || len(set) < 2 || len(set) > 32 {
		return identity.FeatureField{}, invalidWork()
	}
	grant, err := identity.ParseCommandID(b.RecordID)
	if err != nil || grant == b.CommandID {
		return identity.FeatureField{}, invalidWork()
	}
	users := make(map[identity.UserID]struct{}, len(set))
	commands := make(map[identity.CommandID]struct{}, len(set))
	wire := []byte("identity.impersonation.approver-set.v1")
	writeText := func(value string) {
		wire = binary.BigEndian.AppendUint64(wire, uint64(len(value)))
		wire = append(wire, value...)
	}
	writeText(string(b.TenantID))
	writeText(b.RecordID)
	writeText(string(b.CommandID))
	wire = binary.BigEndian.AppendUint64(wire, uint64(len(set)))
	for _, member := range set {
		u, policy := member.User, member.Authorization
		id, err := identity.ParseCommandID(string(member.ApprovalCommandID))
		if err != nil || id == grant || id == b.CommandID || u.Validate(b.TenantID) != nil ||
			u.Status != identity.StatusActive || u.ID == b.UserID || u.ID == identity.UserID(b.ActorID) ||
			policy.Version == 0 || policy.Scope.Validate() != nil ||
			policy.Scope.TenantID != authorization.TenantID(b.TenantID) || policy.Scope.SubjectID != authorization.SubjectID(u.ID) {
			return identity.FeatureField{}, invalidWork()
		}
		if _, duplicate := users[u.ID]; duplicate {
			return identity.FeatureField{}, invalidWork()
		}
		if _, duplicate := commands[id]; duplicate {
			return identity.FeatureField{}, invalidWork()
		}
		users[u.ID], commands[id] = struct{}{}, struct{}{}
		writeText(string(id))
		writeText(string(u.ID))
		wire = binary.BigEndian.AppendUint64(wire, u.Version)
		writeText(policy.Scope.PolicyNamespace)
		wire = binary.BigEndian.AppendUint64(wire, policy.Version)
	}
	digest := sha256.Sum256(wire)
	return identity.FeatureField{Name: impersonationApproverSetField,
		Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

func impersonationStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.start",
		SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func impersonationApproverSetMatches(b identity.CommandBinding, registration FeatureRegistration, lifecycle LifecyclePlan, command identity.Command, set []ImpersonationApproverAdmission) bool {
	spec, ok := command.Feature()
	op := impersonationStartOperation()
	owner := ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}
	before := uint64(len(set)) + 1
	if !ok || spec.Binding != b || spec.Operation != op || registration != (FeatureRegistration{Contributor: owner, Operation: op}) ||
		lifecycle != (LifecyclePlan{EventType: "impersonation.started.v1", BeforeVersion: before, AfterVersion: before + 1}) {
		return false
	}
	expected, err := ImpersonationApproverSetField(b, set)
	if err != nil {
		return false
	}
	for _, field := range spec.Fields {
		if field.Name == expected.Name {
			return field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, expected.Value.Bytes)
		}
	}
	return false
}

// RequireActiveImpersonationApprovers fences every bound reviewer account and
// authorization epoch in the original configurable Start's Apply or final
// commit invocation. The native owner still owns the original decisions,
// complete ordinal set, and current policy checks. Nothing is authorized by
// merely constructing the structural command field.
func (w Work) RequireActiveImpersonationApprovers(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, set []ImpersonationApproverAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	binding, registration, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !impersonationApproverSetMatches(binding, registration, lifecycle, command, set) {
		return w.fail(ctx, invalidWork())
	}
	original := w.state.featureApplyCommand
	if !w.state.featureApplying {
		original = w.state.featureCommitCommand
	}
	if original == nil || *original != command {
		return w.fail(ctx, invalidWork())
	}
	for _, member := range set {
		if err := w.requireActiveUserRecord(ctx, member.User); err != nil {
			return err
		}
		// Use the reviewer's local lookup key, not a different Work binding.
		userBinding := binding
		userBinding.UserID = member.User.ID
		if err := w.requireActiveUserAuthorization(ctx, userBinding, member.Authorization); err != nil {
			return err
		}
	}
	return nil
}
