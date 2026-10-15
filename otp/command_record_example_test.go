package otp_test

import (
	"context"
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func ExampleAttemptIssuer_RestoreForCommand() {
	// Illustrative keys and IDs only; production loads independently generated
	// keys and verified original flow context from trusted composition.
	i, _ := otp.NewAttemptIssuer(1, [32]byte{1})
	destination, _ := otp.NewDestinationInput("user@example.test")
	flow, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"})
	c, _ := otp.NewContinuation(otp.DigestScopeSpec{TenantID: "tenant", Purpose: otp.PurposeStepUp, SubjectID: "subject", Channel: otp.ChannelEmail, Destination: destination, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 1, Generation: 1}, flow, session.RememberPolicy{})
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.step-up", SchemaID: "identity-otp-step-up", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "subject", ActorID: "service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "target"}
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, op, c, otp.AttemptModeConsume, 1, code)
	if err != nil {
		panic("attempt preparation failed")
	}
	record, err := i.SealForCommand(a)
	if err != nil {
		panic("attempt custody failed")
	}
	restored, err := i.RestoreForCommand(record, code)
	if err != nil {
		panic("attempt restoration failed")
	}
	original, _ := a.Recovery()
	recovery, _ := restored.Recovery()
	fmt.Println(recovery == original)
	// Only the native counted primary transaction can establish verification
	// and reservation. This example establishes neither.
	// Output: true
}
