package password

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

// HashPreparationConfig freezes trusted pre-transaction composition. Every
// field is required. Byte bounds are inclusive, positive and at most 1MiB;
// Timeout is positive and at most 10 seconds. DummyHash must exactly match the
// selected primitive profile. Policy must enable HIBP for the supported creating
// operations. Unselected operations cannot reach Collect or hashing.
//
// Collect is the platform's bounded provider orchestration, not request input or
// an acceptance override. It returns provenance-valid original signals for the
// supplied exact context, including the risk-owned HIBP signal. Prepare requires
// the complete set; PrepareProtected requires providers only, without velocity.
// It must
// honor ctx, synchronously borrow candidate custody, retain no candidate and
// return no more than the selected policy's mandatory signal count. Structural
// validation does not establish provider provenance: reference composition must
// wire the real owned adapters. Now and all dependencies must be concurrent-safe.
// The caller owns primitive/provider shutdown and password destruction.
type HashPreparationConfig struct {
	Primitive                  *primitive.Service
	MinimumBytes, MaximumBytes uint32
	Timeout                    time.Duration
	DummyHash                  primitive.EncodedHash
	Policy                     risk.Policy
	Now                        func() time.Time
	Collect                    func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error)
}

// HashPreparer performs the shared HIBP/risk-gated raw-byte hashing used before
// native password-creating transactions. It owns no resource, goroutine, retry,
// store, credential authority or transaction. It cannot persist a password,
// issue a proof/session or authorize a protected mutation. Zero denies.
// Copies share immutable closure custody and support concurrent calls under
// the configured dependencies' contracts. No candidate is retained after calls.
type HashPreparer struct {
	prepare          func(context.Context, primitive.Secret, risk.Context) (primitive.EncodedHash, risk.Assessment, error)
	prepareProtected func(context.Context, primitive.Secret, risk.Context) (primitive.EncodedHash, risk.ProtectedProviderAssessment, error)
}

// NewHashPreparer validates explicit composition without callbacks, crypto or
// IO. Disabled HIBP, incomplete configuration or mismatched dummy policy deny.
// The existing primitive retains cryptographic/resource ownership; the risk
// owner retains acceptance/outage policy. There is no unchecked hash method.
func NewHashPreparer(c HashPreparationConfig) (*HashPreparer, error) {
	w := passwordWork{primitive: c.Primitive, minimum: c.MinimumBytes, maximum: c.MaximumBytes, timeout: c.Timeout, dummy: c.DummyHash}
	if !w.valid() || c.Timeout > 10*time.Second || c.Now == nil || c.Collect == nil {
		return nil, ErrPasswordWork
	}
	if _, err := c.Policy.HIBPConfiguration(); err != nil {
		return nil, ErrPasswordWork
	}
	s := passwordScreening{policy: c.Policy, now: c.Now, collect: c.Collect}
	return &HashPreparer{prepare: func(ctx context.Context, candidate primitive.Secret, binding risk.Context) (primitive.EncodedHash, risk.Assessment, error) {
		return w.newScreenedHash(ctx, candidate, s, binding)
	}, prepareProtected: func(ctx context.Context, candidate primitive.Secret, binding risk.Context) (primitive.EncodedHash, risk.ProtectedProviderAssessment, error) {
		protected := s
		protected.protectedProviders = true
		hash, assessment, err := w.newScreenedHash(ctx, candidate, protected, binding)
		return hash, risk.ProtectedProviderAssessment{Decision: assessment.Decision, PolicyVersion: assessment.PolicyVersion, Signals: assessment.Signals}, err
	}}, nil
}

// Prepare screens and hashes the exact live caller-owned bytes before any
// transaction. Earlier caller deadlines win. Missing, foreign, breached,
// unavailable or non-Allow signals disclose no hash. Original signals are
// copied and rechecked after crypto; they are never recollected or renewed.
// Cancellation retains context errors; provider/crypto errors and panics redact.
// The returned assessment is an internal summary, NOT one-use risk evidence,
// authentication or mutation authority. The native workflow must independently
// authorize, reserve risk/proof use and recheck current owners in its transaction.
// EncodedHash.String explicitly exposes verifier material for owned persistence;
// never log or return it to a client. Discard every copy after bounded use. Go
// cannot guarantee erasure of immutable encoded strings. Destroy candidate only
// after Prepare returns; the preparer never destroys caller custody.
func (p *HashPreparer) Prepare(ctx context.Context, candidate primitive.Secret, binding risk.Context) (primitive.EncodedHash, risk.Assessment, error) {
	if p == nil || p.prepare == nil {
		return primitive.EncodedHash{}, risk.Assessment{}, ErrPasswordWork
	}
	return p.prepare(ctx, candidate, binding)
}

// PrepareProtected screens and hashes for the closed command-reserved credential
// mutation profile. Required HIBP/provider facts are checked before and after
// crypto without recollection or freshness renewal; only native transaction-
// owned velocity is deferred. Caller velocity and unsupported profiles deny.
// The distinct provider-only result grants no counter allowance or authority:
// the mutation owner must reserve/recheck matching counters atomically with its
// protected effects. Prepare retains its existing complete-assessment behavior.
// Secret ownership, bounds, cancellation and redaction match Prepare.
func (p *HashPreparer) PrepareProtected(ctx context.Context, candidate primitive.Secret, binding risk.Context) (primitive.EncodedHash, risk.ProtectedProviderAssessment, error) {
	if p == nil || p.prepareProtected == nil {
		return primitive.EncodedHash{}, risk.ProtectedProviderAssessment{}, ErrPasswordWork
	}
	return p.prepareProtected(ctx, candidate, binding)
}

func (HashPreparationConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.HashPreparationConfig(redacted)")
}
func (HashPreparationConfig) MarshalJSON() ([]byte, error) { return nil, ErrPasswordWork }
func (HashPreparationConfig) MarshalText() ([]byte, error) { return nil, ErrPasswordWork }
func (HashPreparer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.HashPreparer(redacted)")
}
func (HashPreparer) MarshalJSON() ([]byte, error) { return nil, ErrPasswordWork }
func (HashPreparer) MarshalText() ([]byte, error) { return nil, ErrPasswordWork }
