package otp_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func TestEmailVerificationAttemptBindsRealIdentifierAndOriginalSession(t *testing.T) {
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-verify", SchemaID: "identity.otp.email-verify.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b, _ := commandAttemptScope()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.RecordID, b.ActorID, b.ActorKind = "pending:email", "subject", authorization.SubjectUser
	target, err := otp.NewEmailVerificationTarget(otp.EmailVerificationTargetSpec{IdentifierID: "pending:email", IdentifierVersion: 2, VerificationVersion: 2, FactorVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	scope := digestScopeSpec(t)
	scope.Purpose, scope.AuthorizationBinding = otp.PurposeEmailVerification, [32]byte{}
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
	prepare := func(b identity.CommandBinding, op identity.FeatureOperation, s otp.DigestScopeSpec, f otp.FlowAuthorization, mode otp.AttemptMode) (otp.AttemptCommand, error) {
		c, e := otp.NewContinuation(s, f, session.RememberPolicy{})
		if e != nil {
			return otp.AttemptCommand{}, e
		}
		return issuer.PrepareForCommand(context.Background(), b, op, c, mode, 1, code)
	}
	a, err := prepare(b, op, scope, flow, otp.AttemptModeConsume)
	if err != nil {
		t.Fatal("real identifier binding rejected structured verification target:", err)
	}
	got, selected, err := a.CommandBinding()
	if err != nil || got != b || selected != op {
		t.Fatal("original command changed")
	}
	for name, change := range map[string]func(*identity.CommandBinding, *identity.FeatureOperation, *otp.DigestScopeSpec, *otp.FlowAuthorization, *otp.AttemptMode){
		"foreign-identifier": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.RecordID = "other"
		},
		"synthetic-record": func(b *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.RecordID = s.TargetID
		},
		"foreign-actor": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.ActorID = "other"
		},
		"service-actor": func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"signin-purpose": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.Purpose = otp.PurposeSignin
		},
		"phone-channel": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.Channel = otp.ChannelSMS
		},
		"bare-target": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, s *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			s.TargetID = "pending:email"
		},
		"id-only-session": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, f *otp.FlowAuthorization, _ *otp.AttemptMode) {
			*f, _ = otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"})
		},
		"check-only": func(_ *identity.CommandBinding, _ *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, m *otp.AttemptMode) {
			*m = otp.AttemptModeCheck
		},
		"other-operation": func(b *identity.CommandBinding, op *identity.FeatureOperation, _ *otp.DigestScopeSpec, _ *otp.FlowAuthorization, _ *otp.AttemptMode) {
			op.OperationID, b.OperationID = "identity.otp.signin", "identity.otp.signin"
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding, operation, sc, authorization, mode := b, op, scope, flow, otp.AttemptModeConsume
			change(&binding, &operation, &sc, &authorization, &mode)
			if _, err := prepare(binding, operation, sc, authorization, mode); !errors.Is(err, otp.ErrInvalidAttempt) && !errors.Is(err, otp.ErrInvalidAuthorization) {
				t.Fatal("foreign verification scope admitted", err)
			}
		})
	}
}
