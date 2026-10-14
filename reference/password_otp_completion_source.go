package reference

import (
	"context"
	"slices"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Original send custody is kept separate from current completion admission.
// Restoring the old risk result cannot grant or renew verification allowance.
type passwordOTPCompletionSource struct {
	input        passwordOTPSendInput
	native       otppg.MFALoginSendInput
	completion   otppg.MFALoginCompletion
	primary      passwordpg.MFAPasswordPrimary
	continuation mfa.PartialAuthContinuation
	factor       mfapg.OTPFactorMetadata
	snapshot     mfapg.OTPFactorSnapshot
}

func (s *passwordOTPCompletionSource) destroy() {
	if s != nil {
		clear(s.input.NativeInput)
	}
}

// The verified child selects native continuation attribution; existing native
// journals authenticate original input/output. Neither a fabricated send request
// nor a new intent store, challenge selector, primary or generation is needed.
func (s *passwordOTPSendState) readCompletionSource(ctx context.Context, r mfa.OtpVerifyRequest) (out *passwordOTPCompletionSource, err error) {
	if ctx == nil || s == nil || r.Validate() != nil || r.Enrollment != nil || r.TrustDevice || !slices.Contains(s.config.AllowedOrigins, r.Origin) {
		return nil, invalidPasswordOTPSend()
	}
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	grant, primaryID, _, err := s.issuer.ReadIssuanceOrigin(ctx, s.pool, r.Proof, "identity.mfa.complete")
	if err != nil {
		return nil, err
	}
	payload := grant.Payload()
	if payload.Tenant != string(r.TenantID) || payload.ID != string(r.ContinuationID) || payload.Issuer != s.config.IssuerURL {
		return nil, identity.ForbiddenError{}
	}
	original, err := s.factors.ReadLoginSend(ctx, grant, s.config.IssuerURL)
	if err != nil {
		return nil, err
	}
	if original.CommandID == r.CommandID {
		return nil, identity.ForbiddenError{}
	}
	phase := &passwordOTPSendPhase{state: s}
	if err := phase.compose(); err != nil {
		return nil, err
	}
	query := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: original.CommandID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: passwordOTPSendOperation().OperationID, RecordID: string(original.FactorID)}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Action = authorization.Action(query.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(query.AnonymousFlowID)}
	feature := kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: passwordOTPSendOperation()}
	k, wire, err := phase.coordinator.QueryRequestPreparation(ctx, query, caller, feature, phase)
	defer clear(wire)
	if err != nil {
		return nil, err
	}
	aad, err := phase.inputAAD(k)
	if err != nil {
		return nil, err
	}
	plain, err := phase.open(ctx, aad, wire)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var input passwordOTPSendInput
	if decodePasswordOTPSendJSON(plain, &input) != nil {
		return nil, invalidPasswordOTPSend()
	}
	retained := false
	defer func() {
		if !retained {
			clear(input.NativeInput)
		}
	}()
	b, metadata := input.Root.Binding, mfapg.OTPFactorMetadata(input.Factor)
	if input.Schema != 1 || input.Root.Operation != passwordOTPSendOperation() || b.CommandID != query.CommandID || b.TenantID != query.TenantID || b.AnonymousFlowID != query.AnonymousFlowID || b.UserID != "" || b.ActorID != query.ActorID || b.ActorKind != query.ActorKind || b.RecordID != query.RecordID || b.PolicyID != s.config.PolicyID || b.PolicyVersion != s.config.Coordinator.AdmissionPolicy.PolicyVersion || metadata.ContinuationID != r.ContinuationID || metadata.FactorID != string(original.FactorID) || input.Origin != r.Origin || input.Callback != r.Callback || input.ChildEnvelopeDigest != grant.EnvelopeDigest() || input.PrimaryRecipient.native().Validate() != nil {
		return nil, identity.ForbiddenError{}
	}
	root, err := identity.NewFeaturePreAuthCommand(input.Root, r.Cookie)
	if err != nil {
		return nil, err
	}
	native, err := s.config.Issuance.ReadLoginSend(ctx, root, input.NativeInput)
	if err != nil {
		return nil, err
	}
	bindings, err := native.Continuation.Bindings()
	if err != nil {
		return nil, err
	}
	flow, correlation, valid := bindings.Authorization.MFAContinuation()
	if !valid || correlation.PrimaryCommandID != primaryID || correlation.ContinuationID != identity.CommandID(r.ContinuationID) || correlation.ScopeDigest != metadata.ScopeDigest || native.Recipient.User.ID != metadata.UserID || bindings.Scope.TargetID != string(r.ContinuationID) {
		return nil, identity.ForbiddenError{}
	}
	continuation, err := s.continuation.Read(ctx, grant, s.config.IssuerURL)
	if err != nil {
		return nil, err
	}
	scope, err := continuation.Bindings()
	if err != nil || scope.SourcePreAuthID != r.PreAuthID || scope.Origin != r.Origin || scope.Audience != s.config.Profile.Audience || scope.PolicyVersion != b.PolicyVersion || scope.FactorVersion != metadata.FactorAuthorityVersion || !scope.IssuedAt.Equal(input.ChildIssuedAt) || !scope.ExpiresAt.Equal(input.ChildExpiresAt) {
		return nil, identity.ForbiddenError{}
	}
	primary, err := s.config.Primary.ReadMFAPasswordPrimary(ctx, r.Proof, continuation, flow, r.Caller)
	if err != nil {
		return nil, err
	}
	currentFactor, err := s.factors.Read(ctx, grant, s.config.IssuerURL, metadata.FactorID)
	if err != nil {
		return nil, err
	}
	current, err := currentFactor.Metadata()
	if err != nil {
		return nil, err
	}
	// Failed-code accounting may advance only the shared continuation version;
	// it cannot replace the original selected factor, recipient or authority.
	expected := metadata
	expected.ContinuationVersion = current.ContinuationVersion
	if expected != current {
		return nil, identity.ForbiddenError{}
	}
	output, generation, err := phase.coordinator.QueryFeaturePreparation(ctx, query, caller, feature, phase)
	defer clear(output)
	if err != nil {
		return nil, err
	}
	phase.input = &input
	aad, err = phase.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	plainOutput, err := phase.open(ctx, aad, output)
	if err != nil {
		return nil, err
	}
	defer clear(plainOutput)
	var prepared passwordOTPSendOutput
	if decodePasswordOTPSendJSON(plainOutput, &prepared) != nil || prepared.Schema != 1 || prepared.Generation != generation || len(prepared.OTP) == 0 {
		return nil, invalidPasswordOTPSend()
	}
	defer clear(prepared.OTP)
	completion, err := s.config.Issuance.RestoreLoginCompletion(ctx, root, input.NativeInput, generation, prepared.OTP)
	if err != nil {
		return nil, err
	}
	retained = true
	return &passwordOTPCompletionSource{input: input, native: native, completion: completion, primary: primary, continuation: continuation, factor: current, snapshot: currentFactor}, nil
}
