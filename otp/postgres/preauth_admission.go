package postgres

import (
	"context"
	"crypto/hmac"
	"fmt"
	"time"

	"github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Private admission has no independently usable public store, transaction or
// callback. Native phase composition must supply the sole coordinator's live
// handle, resolve command replay first, then enforce other current authority
// before it locks shared lockouts or charges the challenge. This profile proves
// only actual cookie possession and exact current primary flow/ownership.
type preAuthProfile struct {
	config sessionpg.Config
	keys   map[uint32]session.DigestKey
}

func (*preAuthProfile) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreAuthProfile(redacted)"))
}

func newPreAuthProfile(config sessionpg.Config, material map[uint32][]byte) (*preAuthProfile, error) {
	if !validSchema(config.Schema) || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute || len(material) < 1 || len(material) > 8 {
		return nil, ErrInvalidConfiguration
	}
	keys := make(map[uint32]session.DigestKey, len(material))
	for version, raw := range material {
		if len(raw) < 32 || len(raw) > 64 {
			return nil, ErrInvalidConfiguration
		}
		var nonzero byte
		for _, b := range raw {
			nonzero |= b
		}
		if nonzero == 0 {
			return nil, ErrInvalidConfiguration
		}
		key, err := session.NewDigestKey(version, raw)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		keys[version] = key
	}
	return &preAuthProfile{config: config, keys: keys}, nil
}

// Authenticate original encrypted custody without inspecting the OTP itself.
// The commitment is computed from the actual submitted bearer, not from request
// digest fields or fresh primary intent. No time is synthesized and no stored
// challenge comparison is repeated. Live primary expiry belongs to admission.
func (c *AttemptCodec) authenticatePreAuth(ctx context.Context, p *preAuthProfile, command identity.Command, plan kernel.OTPAttemptPlan) (session.PreAuthTransaction, error) {
	spec, ok := command.Feature()
	cookie, present := command.PreAuthCookie()
	if !ok || !present {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	return c.authenticatePreAuthSpec(ctx, p, spec, plan, cookie)
}

// Protected phase handles borrow no code. Independently borrowed cookie custody
// is authenticated against the same immutable original spec without constructing
// a synthetic code-bearing command or adopting a primary flow projection.
func (c *AttemptCodec) authenticatePreAuthSpec(ctx context.Context, p *preAuthProfile, spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan, cookie authentication.BearerCredential) (session.PreAuthTransaction, error) {
	bad := func(err error) (session.PreAuthTransaction, error) { return session.PreAuthTransaction{}, err }
	if ctx == nil || c == nil || c.crypto == nil || p == nil || len(p.keys) == 0 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	record, err := c.restoreRecord(spec)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	// restoreRecord has authenticated the unique named version. Never substitute
	// a plan-supplied version even if that version is also retained locally.
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
	original, bound := continuation.Authorization.PreAuthTransaction()
	if !bound {
		return bad(ErrInvalidCommand)
	}
	s, err := original.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	key, retained := p.keys[s.Cookie.KeyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	actual, err := token.PreAuthDigest(key, s.Binding)
	if err != nil || actual.KeyVersion != s.Cookie.KeyVersion || !hmac.Equal(actual.Sum[:], s.Cookie.Sum[:]) {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return original, nil
}

// This bridge borrows only sealed native-phase handles in production. Tests
// borrow their owned pgx transaction. Nil custody selects issued admission;
// non-nil custody must be the exact live current-generation reservation binding,
// not a request value or timeout-derived proof. Takeover/release use distinct
// owner operations; this function cannot authorize either or renew validity.
func admitPreAuth[R sessionpg.SessionRows](ctx context.Context, q sessionpg.SessionQueryer[R], p *preAuthProfile, c *AttemptCodec, command identity.Command, plan kernel.OTPAttemptPlan, custody *kernel.OTPReservationBinding) (session.PreAuthTransaction, error) {
	original, err := c.authenticatePreAuth(ctx, p, command, plan)
	if err != nil {
		return session.PreAuthTransaction{}, err
	}
	if custody == nil {
		err = sessionpg.RequirePreAuth(ctx, q, p.config, original)
	} else {
		spec, _ := command.Feature()
		if custody.Command != spec.Binding || custody.Plan != plan || custody.Fingerprint == ([32]byte{}) || custody.Generation == 0 || custody.PreviousGeneration != 0 {
			return session.PreAuthTransaction{}, ErrInvalidCommand
		}
		use := sessionpg.PreAuthUse{Command: custody.Command, Fingerprint: custody.Fingerprint, Generation: custody.Generation}
		err = sessionpg.RequireReservedPreAuth(ctx, q, p.config, original, use)
	}
	if err != nil {
		return session.PreAuthTransaction{}, err
	}
	if err := ctx.Err(); err != nil {
		return session.PreAuthTransaction{}, err
	}
	return original, nil
}
