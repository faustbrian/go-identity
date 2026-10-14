package reference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func (s *magicLinkTOTPService) readRecoveryInput(ctx context.Context, r mfa.RecoveryUseRequest, rateSource bool) (*magicTOTPInput, error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return nil, invalidTOTPCompletion()
	}
	return s.readNativeMFAInput(ctx, nativeMFAOriginalInput{TenantID: r.TenantID, CommandID: r.CommandID, ChallengeID: r.ContinuationID, PreAuthID: r.PreAuthID, Proof: r.Proof, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Callback: r.Callback, Network: r.Network, Device: r.Device, recovery: &r}, rateSource)
}

// Original recovery intent contains only submitted correlation. Mutable set,
// factor, attempt, policy epochs and generated sessions cannot change a retry's
// identity. The issuer authenticates proof bytes before this pure construction.
func (s *magicLinkTOTPState) originalRecoveryCommand(r mfa.RecoveryUseRequest, proof [32]byte) (identity.Command, error) {
	if s == nil || proof == ([32]byte{}) || r.Validate() != nil || s.config.Coordinator.AdmissionPolicy == nil {
		return identity.Command{}, invalidTOTPCompletion()
	}
	op := recoveryCompletionOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config.PolicyID, PolicyVersion: s.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
	frame, err := json.Marshal(struct {
		Profile, Origin, Callback, Network, Device, Continuation string
		Proof                                                    [32]byte
	}{s.config.ConfigurationID, r.Origin, r.Callback, r.Network, r.Device, string(r.ContinuationID), proof})
	defer clear(frame)
	if err != nil {
		return identity.Command{}, invalidTOTPCompletion()
	}
	intent := sha256.Sum256(frame)
	return identity.NewFeatureRecoveryCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(intent[:])}}}}, r.RecoveryCode, r.Cookie)
}

func recoveryCompletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-use", SchemaID: "mfa-recovery-use", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
