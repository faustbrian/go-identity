package postgres

import (
	"context"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MapPreAuth maps complete original-flow attempt custody and freezes the actual
// submitted flow cookie separately from scalar fields and encrypted persistence.
// Cookie must be a canonical session token, never a caller-supplied digest. The
// underlying Map profile, deadlines, retained-key behavior and original code
// custody remain unchanged. Legacy ID-only continuation is rejected here.
//
// This is NOT cookie verification or current-flow admission: native phases must
// derive its commitment under the exact retained pre-auth key and compare the
// original primary record, policy and ownership. Wrong but syntactically valid
// cookies remain distinct submitted intent until that admission rejects them.
// The coordinator fingerprints the bearer independently; it is never stored in
// Feature fields, attempt envelopes, safe collision fields or recovery outputs.
// Map once and preserve the resulting command through ambiguity; never remap a
// retry. No SQL, callbacks, network, goroutines or independent transaction run.
// Failed mapping returns zero outputs and redacted errors. Discard all bearer
// and code copies on terminal outcomes; Go cannot guarantee complete erasure.
func (c *AttemptCodec) MapPreAuth(ctx context.Context, a otp.AttemptCommand, digestKeyVersion uint32, spec identity.FeatureCommandSpec, cookie auth.BearerCredential) (identity.Command, postgres.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, postgres.OTPAttemptPlan, error) {
		return identity.Command{}, postgres.OTPAttemptPlan{}, err
	}
	if ctx == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	if _, err := session.ParseToken(cookie.Token()); err != nil {
		return bad(ErrInvalidCommand)
	}
	b, err := a.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	continuation, err := b.Continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if _, bound := continuation.Authorization.PreAuthTransaction(); !bound {
		return bad(ErrInvalidCommand)
	}
	command, plan, err := c.Map(ctx, a, digestKeyVersion, spec)
	if err != nil {
		return bad(err)
	}
	metadata, _ := command.Feature()
	code, _ := command.OneTimeCode()
	command, err = identity.NewFeatureOneTimeCodePreAuthCommand(metadata, code, cookie)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return command, plan, nil
}
