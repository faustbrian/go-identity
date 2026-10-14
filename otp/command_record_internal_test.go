package otp

import (
	"context"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Only internal corruption can remove code custody after successful preparation.
// Keep the defensive seal failure redacted rather than signing incomplete state.
func TestCommandRecordInternalLostCodeCannotBeSealed(t *testing.T) {
	authority, err := NewFlowAuthorization(FlowAuthorizationSpec{Kind: FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := NewDestinationInput("user@example.test")
	c, err := NewContinuation(DigestScopeSpec{TenantID: "tenant", Purpose: PurposePasswordReset, SubjectID: "subject", Channel: ChannelEmail, Destination: destination, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 1, Generation: 1}, authority, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.password-reset", SchemaID: "identity-otp-password-reset", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "subject", ActorID: "service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "target"}
	i, _ := NewAttemptIssuer(7, [32]byte{9})
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, op, c, AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	a.state.code = auth.OneTimeCode{}
	if _, err := i.SealForCommand(a); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatal("lost private code signed", err)
	}
}
