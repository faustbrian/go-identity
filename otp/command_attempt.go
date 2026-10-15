package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type attemptCommandScope struct {
	binding   identity.CommandBinding
	operation identity.FeatureOperation
	digest    [32]byte
}

// PrepareForCommand creates one immutable code submission bound to the exact
// consuming command ID and complete trusted structural command/operation scope.
// Select operation from composition, never a request. Root validation freezes
// canonical IDs, explicit user/anonymous namespace, actor, schema and policy.
// Tenant and user subject must match the OTP continuation; anonymous commands
// require its empty pre-account subject. Required record target must match the
// continuation's workflow target. No purpose/permission/current authorization
// is inferred from names: the owning adapter must enforce native operation
// semantics and original pre-auth/session provenance against primary state.
// No caller attempt ID/fingerprint is accepted. Changing any command field
// changes the fingerprint. Preserve the same object through retries; recovery
// carries both original command and attempt identities without code custody.
// This is preparation only, not command admission, reservation or execution.
// Legacy Prepare keeps its exact unbound fingerprint profile; durable command
// adapters must require CommandBinding and reject unbound preparations.
// The explicit MFA arm is the sole exception to the empty pre-account subject:
// its real user remains inside purpose-bound OTP scope while the exact consuming
// MFA command retains the original anonymous browser namespace. Ordinary OTP
// signin/check operations cannot select that arm or substitute a live session.
// Context/entropy/custody semantics are identical to Prepare. Invalid structural
// or mismatched scope returns ErrInvalidAttempt without underlying input/errors.
func (i AttemptIssuer) PrepareForCommand(ctx context.Context, b identity.CommandBinding, operation identity.FeatureOperation, c Continuation, mode AttemptMode, expectedVersion uint64, code auth.OneTimeCode) (AttemptCommand, error) {
	command, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: operation})
	if e != nil || c.state == nil {
		return AttemptCommand{}, ErrInvalidAttempt
	}
	frozen, _ := command.Feature()
	b, operation = frozen.Binding, frozen.Operation
	if !validAttemptCommandScope(b, operation, c, mode) {
		return AttemptCommand{}, ErrInvalidAttempt
	}
	s := &attemptCommandScope{binding: b, operation: operation, digest: attemptCommandDigest(b, operation)}
	return i.prepareWithCommand(ctx, rand.Reader, c, mode, expectedVersion, code, s)
}

// MFA retains a real subject under the original anonymous browser namespace.
// Only its explicit custody and exact consuming operation admit that combination;
// the ordinary pre-account OTP profile and released fingerprint bytes stay intact.
func validAttemptCommandScope(b identity.CommandBinding, op identity.FeatureOperation, c Continuation, mode AttemptMode) bool {
	if c.state == nil || string(b.TenantID) != c.state.bindings.Scope.TenantID {
		return false
	}
	scope := c.state.bindings.Scope
	if original, binding, bound := c.state.bindings.Authorization.MFAContinuation(); bound {
		p, err := original.Bindings()
		return err == nil && mode == AttemptModeConsume && scope.Purpose == PurposeMFA &&
			op == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify",
				SchemaID: "mfa-otp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted,
				SubjectRequirement: identity.FeatureSubjectAnonymousFlow}) &&
			b.UserID == "" && b.RecordID == "" && b.AnonymousFlowID == string(p.Binding.ID) &&
			b.CommandID != binding.PrimaryCommandID && b.CommandID != binding.ContinuationID &&
			scope.SubjectID == string(binding.SubjectID) && scope.TargetID == string(binding.ContinuationID)
	}
	if string(b.UserID) != scope.SubjectID || op.RecordRequirement == identity.FeatureRecordRequired && b.RecordID != scope.TargetID {
		return false
	}
	if record, bound := c.state.bindings.Authorization.PreAuthTransaction(); bound && b.AnonymousFlowID != "" {
		original, _ := record.Bindings()
		return b.AnonymousFlowID == string(original.Binding.ID)
	}
	return true
}

// CommandBinding returns owned structural command/operation declarations, not
// authentication or transaction authority. Zero and legacy unbound preparations
// return ErrInvalidAttempt. Copies cannot change the frozen submission. Never
// log/serialize this projection; it contains private IDs. Durable adapters must
// match it to their exact native command and registered coordinator operation.
func (a AttemptCommand) CommandBinding() (identity.CommandBinding, identity.FeatureOperation, error) {
	if a.state == nil || a.state.command == nil {
		return identity.CommandBinding{}, identity.FeatureOperation{}, ErrInvalidAttempt
	}
	return a.state.command.binding, a.state.command.operation, nil
}

// This is a bounded structural scope digest inside the keyed OTP fingerprint,
// NOT the authoritative RFC8949 command fingerprint owned by the coordinator.
// All fields have already passed root bounds before allocation. No secret code
// enters SHA-256; opaque code binding remains inside authentication's HMAC.
func attemptCommandDigest(b identity.CommandBinding, d identity.FeatureOperation) [32]byte {
	encoded := []byte("identity-otp-command-scope-v1\x00")
	for _, value := range []string{string(b.CommandID), string(b.TenantID), string(b.UserID), b.AnonymousFlowID, string(b.ActorID), string(b.ActorKind), b.OperationID, b.PolicyID, b.SchemaID, b.CorrelationID, b.RecordID, d.Owner, d.OperationID, d.SchemaID} {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(value)))
		encoded = append(encoded, value...)
	}
	encoded = binary.BigEndian.AppendUint64(encoded, b.PolicyVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, b.SchemaVersion)
	encoded = append(encoded, byte(b.LinkMode))
	encoded = binary.BigEndian.AppendUint32(encoded, d.SchemaVersion)
	encoded = append(encoded, byte(d.RecordRequirement), byte(d.SubjectRequirement))
	defer clear(encoded)
	return sha256.Sum256(encoded)
}
