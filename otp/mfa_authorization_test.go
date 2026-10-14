package otp_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func mfaFlowBinding() otp.MFAFlowBinding {
	return otp.MFAFlowBinding{PrimaryCommandID: "AgICAgICAgICAgICAgICAg",
		ContinuationID: "AwMDAwMDAwMDAwMDAwMDAw", ScopeDigest: [32]byte{1}, SubjectID: "subject"}
}

func TestMFAOTPAttemptBindsConsumedPrimaryWithoutChangingCommandNamespace(t *testing.T) {
	p := boundPreAuthSpec(t)
	original, _ := session.NewPreAuthTransaction(p)
	meta := mfaFlowBinding()
	flow, _ := otp.NewMFAFlowAuthorization(original, meta)
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose, scope.SubjectID, scope.TargetID = otp.PurposeMFA, string(meta.SubjectID), string(meta.ContinuationID)
	continuation, err := otp.NewContinuation(scope, flow, p.Binding.Intent.Remember)
	if err != nil {
		t.Fatal(err)
	}
	b, op := commandAttemptScope()
	b.CommandID, b.UserID, b.RecordID, b.AnonymousFlowID = "BAQEBAQEBAQEBAQEBAQEBA", "", "", string(p.Binding.ID)
	op = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{9})
	code, _ := auth.NewOneTimeCode("123456")
	a, err := issuer.PrepareForCommand(context.Background(), b, op, continuation, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal("original MFA child cannot prepare purpose-bound OTP consumption", err)
	}
	sealed, err := issuer.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.VerifyCommandRecord(sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.RestoreForCommand(sealed, code); err != nil {
		t.Fatal("original MFA attempt could not restore", err)
	}
	for _, change := range []func(*identity.CommandBinding, *identity.FeatureOperation){
		func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.AnonymousFlowID = "foreign" },
		func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.CommandID = meta.PrimaryCommandID },
		func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.CommandID = meta.ContinuationID },
		func(b *identity.CommandBinding, _ *identity.FeatureOperation) {
			b.UserID, b.AnonymousFlowID = meta.SubjectID, ""
		},
		func(b *identity.CommandBinding, op *identity.FeatureOperation) {
			b.OperationID, op.OperationID = "identity.otp.signin", "identity.otp.signin"
		},
	} {
		binding, operation := b, op
		change(&binding, &operation)
		if _, err := issuer.PrepareForCommand(context.Background(), binding, operation, continuation, otp.AttemptModeConsume, 1, code); err == nil {
			t.Fatal("foreign/mixed MFA attempt admitted")
		}
		altered := sealed
		altered.Binding, altered.Operation = binding, operation
		altered.Attempt.CommandID = binding.CommandID
		if issuer.VerifyCommandRecord(altered) == nil {
			t.Fatal("sealed MFA record admitted changed command authority")
		}
	}
	if _, err := issuer.PrepareForCommand(context.Background(), b, op, continuation, otp.AttemptModeCheck, 1, code); err == nil {
		t.Fatal("MFA verification downgraded into nonconsuming check")
	}
}

func TestMFAOTPAuthorizationDoesNotReopenOrdinaryPreAuth(t *testing.T) {
	p := boundPreAuthSpec(t)
	original, err := session.NewPreAuthTransaction(p)
	if err != nil {
		t.Fatal(err)
	}
	binding := mfaFlowBinding()
	a, err := otp.NewMFAFlowAuthorization(original, binding)
	if err != nil {
		t.Fatal("MFA consumed-primary custody unavailable", err)
	}
	s, err := a.Bindings()
	if err != nil || s.Kind != otp.FlowAuthorizationMFAContinuation || s.MFAContinuationID != binding.ContinuationID || s.PreAuthTransactionID != "" || s.AuthenticatedSessionID != "" {
		t.Fatal("MFA authorization collapsed into ordinary flow")
	}
	if _, ok := a.PreAuthTransaction(); ok {
		t.Fatal("MFA custody reopened the original preauth state machine")
	}
	if _, ok := a.AuthenticatedSession(); ok {
		t.Fatal("partial authentication became a full session")
	}
	got, retained, ok := a.MFAContinuation()
	if !ok || got != original || retained != binding {
		t.Fatal("original consumed-primary references lost")
	}
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose, scope.SubjectID, scope.TargetID = otp.PurposeMFA, string(binding.SubjectID), string(binding.ContinuationID)
	c, err := otp.NewContinuation(scope, a, p.Binding.Intent.Remember)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := c.Bindings()
	legacy, _ := otp.NewBoundPreAuthAuthorization(original)
	other, err := otp.NewContinuation(scope, legacy, p.Binding.Intent.Remember)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := other.Bindings()
	if old.Scope.AuthorizationBinding == base.Scope.AuthorizationBinding {
		t.Fatal("MFA and ordinary preauth share authority framing")
	}
	for _, change := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeSignin },
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeStepUp },
		func(s *otp.DigestScopeSpec) { s.TenantID = "foreign" },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "foreign" },
		func(s *otp.DigestScopeSpec) { s.TargetID = "foreign" },
	} {
		changed := scope
		change(&changed)
		if _, err := otp.NewContinuation(changed, a, p.Binding.Intent.Remember); !errors.Is(err, otp.ErrInvalidAuthorization) {
			t.Fatal("MFA scope substituted")
		}
	}
	policy, _ := p.Binding.Intent.Remember.Bindings()
	policy.Choice = session.PersistentSession
	upgraded, _ := session.NewRememberPolicy(policy)
	if _, err := otp.NewContinuation(scope, a, upgraded); err == nil {
		t.Fatal("MFA upgraded original remember policy")
	}
}

func TestMFAOTPAuthorizationRejectsMissingAndMixedCustody(t *testing.T) {
	original, _ := session.NewPreAuthTransaction(boundPreAuthSpec(t))
	for _, change := range []func(*otp.MFAFlowBinding){
		func(b *otp.MFAFlowBinding) { b.PrimaryCommandID = "" },
		func(b *otp.MFAFlowBinding) { b.ContinuationID = "" },
		func(b *otp.MFAFlowBinding) { b.ContinuationID = b.PrimaryCommandID },
		func(b *otp.MFAFlowBinding) { b.ScopeDigest = [32]byte{} },
		func(b *otp.MFAFlowBinding) { b.SubjectID = "" },
		func(b *otp.MFAFlowBinding) { b.SubjectID = "not canonical" },
	} {
		b := mfaFlowBinding()
		change(&b)
		if _, err := otp.NewMFAFlowAuthorization(original, b); err == nil {
			t.Fatal("malformed MFA custody accepted")
		}
	}
	if _, err := otp.NewMFAFlowAuthorization(session.PreAuthTransaction{}, mfaFlowBinding()); err == nil {
		t.Fatal("missing original primary flow accepted")
	}
	for _, s := range []otp.FlowAuthorizationSpec{
		{Kind: otp.FlowAuthorizationMFAContinuation, MFAContinuationID: mfaFlowBinding().ContinuationID},
		{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID(), MFAContinuationID: mfaFlowBinding().ContinuationID},
		{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session", MFAContinuationID: identity.CommandID(mfaFlowBinding().ContinuationID)},
	} {
		if _, err := otp.NewFlowAuthorization(s); err == nil {
			t.Fatal("scalar or mixed MFA projection fabricated complete custody")
		}
	}
}
