package postgres

import (
	"context"
	"crypto/hmac"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MapSession maps complete original-session attempt custody and separately
// freezes the actual submitted session token outside scalar/encrypted metadata.
// Token syntax must follow session.ParseToken; no caller-selected digest is
// accepted. Mapping proves neither possession, current activity nor permission.
// The native owner must derive the exact original lookup-key version, compare
// the original session and every applicable primary authority, and consume
// atomically. Map once and retain the command through retry/ambiguity; never
// replace its original record or authentication time with a fresh lookup.
// Bounds, cancellation, code custody and retained wrapping-key policy match Map.
// No SQL, callback, network, goroutine or independent transaction is created.
func (c *AttemptCodec) MapSession(ctx context.Context, attempt otp.AttemptCommand, version uint32, spec identity.FeatureCommandSpec, token auth.BearerCredential) (identity.Command, kernel.OTPAttemptPlan, error) {
	return c.mapSession(ctx, attempt, version, spec, token, nil)
}

// MapSessionWithAuthority additionally freezes original primary-owner
// expectations in the authenticated envelope. It shares MapSession's authority
// limits and secret handling; expectation construction is not live admission.
// Submitted code/token never enter encrypted custody or recovery projections.
func (c *AttemptCodec) MapSessionWithAuthority(ctx context.Context, attempt otp.AttemptCommand, version uint32, spec identity.FeatureCommandSpec, token auth.BearerCredential, original AttemptAuthority) (identity.Command, kernel.OTPAttemptPlan, error) {
	return c.mapSession(ctx, attempt, version, spec, token, &original)
}

func (c *AttemptCodec) mapSession(ctx context.Context, attempt otp.AttemptCommand, version uint32, spec identity.FeatureCommandSpec, token auth.BearerCredential, authority *AttemptAuthority) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	if ctx == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	if _, err := session.ParseToken(token.Token()); err != nil {
		return bad(ErrInvalidCommand)
	}
	b, err := attempt.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	continuation, err := b.Continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if _, bound := continuation.Authorization.AuthenticatedSession(); !bound {
		return bad(ErrInvalidCommand)
	}
	command, plan, err := c.mapAttempt(ctx, attempt, version, spec, authority)
	if err != nil {
		return bad(err)
	}
	metadata, _ := command.Feature()
	code, _ := command.OneTimeCode()
	command, err = identity.NewFeatureOneTimeCodeSessionCommand(metadata, code, token)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return command, plan, nil
}

// Only a derived commitment is compared; this neither adopts current state nor
// supplies primary or policy admission. Native protected phases lend the token
// separately and use the same code-free spec restoration below.
func (c *AttemptCodec) authenticateSession(ctx context.Context, keys map[uint32]session.DigestKey, command identity.Command, plan kernel.OTPAttemptPlan) (session.Session, error) {
	spec, ok := command.Feature()
	token, present := command.SessionToken()
	if !ok || !present {
		return session.Session{}, ErrInvalidCommand
	}
	return c.authenticateSessionSpec(ctx, keys, spec, plan, token)
}

func (c *AttemptCodec) authenticateSessionSpec(ctx context.Context, keys map[uint32]session.DigestKey, spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan, submitted auth.BearerCredential) (session.Session, error) {
	bad := func(err error) (session.Session, error) { return session.Session{}, err }
	if ctx == nil || c == nil || c.crypto == nil || len(keys) < 1 || len(keys) > 8 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	record, err := c.restoreRecord(spec)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	var version uint32
	for _, f := range spec.Fields {
		if f.Name == "otp.digest-key-version" {
			version = uint32(f.Value.Uint64)
		}
	}
	want, err := c.recordPlan(record, version)
	if err != nil || want != plan {
		return bad(ErrInvalidCommand)
	}
	continuation, err := record.Attempt.Continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	original, bound := continuation.Authorization.AuthenticatedSession()
	if !bound {
		return bad(ErrInvalidCommand)
	}
	s, err := original.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	key, retained := keys[s.Lookup.KeyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	token, err := session.ParseToken(submitted.Token())
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	actual, err := token.Digest(key, string(s.TenantID))
	if err != nil || actual.KeyVersion != s.Lookup.KeyVersion || !hmac.Equal(actual.Sum[:], s.Lookup.Sum[:]) {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return original, nil
}
