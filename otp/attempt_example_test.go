package otp_test

import (
	"context"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func ExampleAttemptIssuer() {
	// Synthetic configuration and verified-flow placeholders, not production
	// key custody or current database authority.
	preAuth, _ := identity.ParsePreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ")
	authorization, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuth})
	remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 30 * time.Minute, FreshFor: 15 * time.Minute})
	destination, _ := otp.NewDestinationInput("user@example.test")
	c, e := otp.NewContinuation(otp.DigestScopeSpec{TenantID: "tenant", Purpose: otp.PurposeSignin, SubjectID: "subject", Channel: otp.ChannelEmail, Destination: destination, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 1, Generation: 1}, authorization, remember)
	if e != nil {
		panic("invalid example continuation")
	}
	issuer, _ := otp.NewAttemptIssuer(1, [32]byte{1})
	code, _ := auth.NewOneTimeCode("123456")
	command, e := issuer.Prepare(context.Background(), c, otp.AttemptModeConsume, 1, code)
	if e != nil {
		panic("example preparation unavailable")
	}
	metadata, e := command.Bindings()
	// This proves preparation only, not verification, reservation or login.
	fmt.Println(e == nil && metadata.Mode == otp.AttemptModeConsume)
	// Output: true
}
