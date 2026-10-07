package risk

import (
	"context"
	"fmt"
	"time"
)

// VelocityClosureBinding retains the primary owner's original covered cut.
// ID is its stable keyed cut identity, not an application identifier. Position
// is applied scoped progress (zero for genuinely covered empty history).
// ReplayFrom is the original traversal origin, not proof of coverage before
// JournalStartedAt. The full MaximumWindow ending at ReplayThrough must be
// covered by both traversal and continuous journal provenance. Only configured
// owned adapters may read these facts; they grant no IO or healthy admission.
type VelocityClosureBinding struct {
	ID                                          [32]byte
	Position                                    int64
	ReplayFrom, ReplayThrough, JournalStartedAt time.Time
	MaximumWindow                               time.Duration
}

// VelocityClosure is immutable primary-issued covered-cut custody bound to one
// exact lease. A stable cut without proven coverage must never be issued here.
// Zero is invalid. Copies are concurrency-safe; no serialization is supported.
type VelocityClosure struct{ state *velocityClosure }
type velocityClosure struct {
	lease   *velocityLease
	binding VelocityClosureBinding
	check   func(context.Context) error
}

// Closure records an already acknowledged, covered primary cut. The concrete
// journal supplies a concurrent-safe, context-bounded checker of that exact cut
// and original lease, not a caller-supplied healthy assertion. Construction is
// pure: it neither observes storage nor creates coverage. The selected recovery
// maximum is exactly one hour. Foreign leases, missing provenance/checkers and
// malformed cuts return no custody. No SQL lock may span native publication IO.
func (i VelocityJournalIssuer) Closure(l VelocityLease, b VelocityClosureBinding, check func(context.Context) error) (VelocityClosure, error) {
	if i.journal == nil || l.state == nil || l.state.issuer != i.journal || check == nil || !validVelocityClosure(l.state.binding, b) {
		return VelocityClosure{}, ErrInvalidVelocityRecovery
	}
	return VelocityClosure{state: &velocityClosure{lease: l.state, binding: b, check: check}}, nil
}

// Closure verifies exact configured identity, current original lease and the
// retained primary cut before returning copied facts. Equal projected fields
// cannot rebind custody. Checks do not reset any time or confer healthy admission.
func (v VelocityJournalVerifier) Closure(ctx context.Context, l VelocityLease, c VelocityClosure) (VelocityClosureBinding, error) {
	if v.journalVerifier == nil || l.state == nil || c.state == nil || l.state.issuer != v.journalVerifier || c.state.lease != l.state {
		return VelocityClosureBinding{}, ErrInvalidVelocityRecovery
	}
	if err := checkVelocityLease(ctx, l); err != nil {
		return VelocityClosureBinding{}, err
	}
	if err := checkVelocityAuthority(ctx, c.state.check); err != nil {
		return VelocityClosureBinding{}, err
	}
	return c.state.binding, nil
}

// VelocityPublication is the configured native owner's acknowledgement of one
// exact covered closure. It is distinct from an individual replay acknowledgement
// and does not establish primary confirmation, admission or present native health.
type VelocityPublication struct{ state *velocityPublication }
type velocityPublication struct {
	issuer  *velocityNativeAuthority
	closure *velocityClosure
}

// AcknowledgePublication is called by the privately configured native owner only
// after exact attributable fenced publication IO. It rechecks original primary
// lease and covered-cut custody before exposing acknowledgement. Failed or late
// IO must not call this method. This primitive observes no IO itself and cannot
// attest malicious configuration. Never expose its issuer to ordinary callers.
func (i VelocityNativeIssuer) AcknowledgePublication(ctx context.Context, l VelocityLease, c VelocityClosure) (VelocityPublication, error) {
	if i.native == nil {
		return VelocityPublication{}, ErrInvalidVelocityRecovery
	}
	if _, err := (VelocityJournalVerifier{journalVerifier: i.native.journal}).Closure(ctx, l, c); err != nil {
		return VelocityPublication{}, err
	}
	return VelocityPublication{state: &velocityPublication{issuer: i.native, closure: c.state}}, nil
}

// Publication checks the exact configured native issuer, original closure and
// current primary custody. PostgreSQL must independently authenticate these
// facts and confirm publication atomically; this read cannot promote the epoch
// to healthy or authorize a debit. A second equivalent closure is not the same
// acknowledgement. Cancellation/deadlines survive; other failures are redacted.
func (v VelocityNativeVerifier) Publication(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication) (VelocityClosureBinding, error) {
	if v.nativeVerifier == nil || p.state == nil || c.state == nil || p.state.issuer != v.nativeVerifier || p.state.closure != c.state {
		return VelocityClosureBinding{}, ErrInvalidVelocityRecovery
	}
	return (VelocityJournalVerifier{journalVerifier: v.nativeVerifier.journal}).Closure(ctx, l, c)
}

func validVelocityClosure(l VelocityLeaseBinding, b VelocityClosureBinding) bool {
	if b.ID == [32]byte{} || b.Position < 0 || b.MaximumWindow != time.Hour || !velocityWireTime(b.ReplayFrom) || !velocityWireTime(b.ReplayThrough) || !velocityWireTime(b.JournalStartedAt) || !b.ReplayThrough.Before(l.ExpiresAt) {
		return false
	}
	required := b.ReplayThrough.Add(-b.MaximumWindow)
	return !b.ReplayFrom.After(required) && !b.JournalStartedAt.After(required)
}

func (VelocityClosureBinding) Format(s fmt.State, _ rune)   { velocityRedacted(s) }
func (VelocityClosure) Format(s fmt.State, _ rune)          { velocityRedacted(s) }
func (VelocityPublication) Format(s fmt.State, _ rune)      { velocityRedacted(s) }
func (VelocityClosureBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityClosure) MarshalJSON() ([]byte, error)        { return nil, ErrSensitiveSerialization }
func (VelocityPublication) MarshalJSON() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (VelocityClosureBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityClosure) MarshalText() ([]byte, error)        { return nil, ErrSensitiveSerialization }
func (VelocityPublication) MarshalText() ([]byte, error)    { return nil, ErrSensitiveSerialization }
