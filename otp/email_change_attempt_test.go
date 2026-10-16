package otp_test

import (
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func TestEmailChangeAttemptBindsOpaqueOriginAndSelfSession(t *testing.T) {
	b, _ := commandAttemptScope()
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-change-confirm", SchemaID: "identity.otp.email-change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	b.ActorKind, b.ActorID, b.RecordID = authorization.SubjectUser, "subject", "pending:email"
	target, err := otp.NewEmailChangeTarget(otp.EmailChangeTargetSpec{OriginCommandID: "AgICAgICAgICAgICAgICAg", OriginOutputDigest: [32]byte{3}, IdentifierID: "pending:email", IdentifierVersion: 1, VerificationVersion: 1, FactorVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	scope := digestScopeSpec(t)
	scope.Purpose, scope.AuthorizationBinding = otp.PurposeEmailChange, [32]byte{}
	scope.TargetID, _ = target.ScopeTarget()
	record, err := session.NewSession(originalSessionSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundSessionAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	prepare := func(b identity.CommandBinding, op identity.FeatureOperation, s otp.DigestScopeSpec, f otp.FlowAuthorization, mode otp.AttemptMode) error {
		c, err := otp.NewContinuation(s, f, session.RememberPolicy{})
		if err != nil {
			return err
		}
		_, err = issuer.PrepareForCommand(context.Background(), b, op, c, mode, 1, code)
		return err
	}
	if err := prepare(b, op, scope, flow, otp.AttemptModeConsume); err != nil {
		t.Fatal("opaque original change target rejected", err)
	}
	for _, mutate := range []func(*identity.CommandBinding, *identity.FeatureOperation, *otp.DigestScopeSpec, *otp.FlowAuthorization, *otp.AttemptMode){
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.ActorID = "foreign"
		},
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.Purpose = otp.PurposeEmailVerification
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.Channel = otp.ChannelSMS
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.TargetID = "pending:email"
		},
		func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.CommandID = "AgICAgICAgICAgICAgICAg"
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, f *otp.FlowAuthorization, _ *otp.AttemptMode) {
			*f, _ = otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"})
		},
		func(_ *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, m *otp.AttemptMode) {
			*m = otp.AttemptModeCheck
		},
		func(b *identity.CommandBinding, op *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.OperationID, op.OperationID = "identity.otp.signin", "identity.otp.signin"
		},
	} {
		binding, operation, sc, authorization, mode := b, op, scope, flow, otp.AttemptModeConsume
		mutate(&binding, &operation, &sc, &authorization, &mode)
		if prepare(binding, operation, sc, authorization, mode) == nil {
			t.Fatal("unselected scope entered primary OTP consumption")
		}
	}
}
