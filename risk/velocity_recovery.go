package risk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

var (
	// ErrInvalidVelocityRecovery identifies zero, foreign or malformed custody.
	ErrInvalidVelocityRecovery = errors.New("risk: invalid velocity recovery custody")
	// ErrVelocityRecoveryUnavailable identifies unresolved history or unavailable
	// current primary ownership. It never means noncommit or permission to retry.
	ErrVelocityRecoveryUnavailable = errors.New("risk: velocity recovery unavailable")
)

// VelocityJournalIssuer is an immutable primary-owner issuance capability.
// Only trusted composition may retain it and give it to the concrete journal.
// It owns no storage, clock or goroutine. Copies share issuance rights; zero is
// invalid. Never expose it through ordinary application handles/configuration.
type VelocityJournalIssuer struct{ journal *velocityJournalAuthority }

// VelocityJournalVerifier can read/check only its configured journal's custody.
// It cannot issue leases, history or native acknowledgements. Bindings are
// private adapter data, not HTTP output or effect/healthy-state permission.
type VelocityJournalVerifier struct{ journalVerifier *velocityJournalAuthority }

// VelocityNativeIssuer is the separate native-owner acknowledgement capability.
// Trusted composition retains it privately in the concrete native adapter.
// Acknowledge must be called only after exact attributable native IO success;
// this primitive cannot observe IO or attest a malicious configurator's honesty.
// Journal issuers/verifiers and operational handles cannot recover this value.
type VelocityNativeIssuer struct{ native *velocityNativeAuthority }

// VelocityNativeVerifier reads acknowledgements from exactly its configured
// native issuer. It grants no issuance, persistence, debit or health authority.
type VelocityNativeVerifier struct{ nativeVerifier *velocityNativeAuthority }

type velocityJournalAuthority struct{ native *velocityNativeAuthority }
type velocityNativeAuthority struct{ journal *velocityJournalAuthority }

// NewVelocityRecoveryAuthorities creates one isolated capability graph without
// IO. Reference composition must give primary issuance only to the journal,
// native issuance only to the concrete projection, and retain verification
// views privately. A second call creates foreign authority, not equivalent
// permission. Constructors establish capability identity, not storage truth.
// Public types have deliberately distinct representations: Go struct conversion
// must not promote verification or primary issuance into native issuance.
func NewVelocityRecoveryAuthorities() (VelocityJournalIssuer, VelocityJournalVerifier, VelocityNativeIssuer, VelocityNativeVerifier) {
	j := &velocityJournalAuthority{}
	n := &velocityNativeAuthority{journal: j}
	j.native = n
	return VelocityJournalIssuer{journal: j}, VelocityJournalVerifier{journalVerifier: j}, VelocityNativeIssuer{native: n}, VelocityNativeVerifier{nativeVerifier: n}
}

// Verifier derives only the primary issuer's read/check capability. It cannot
// recover native issuance; zero returns no verifier and a redacted error.
func (i VelocityJournalIssuer) Verifier() (VelocityJournalVerifier, error) {
	if i.journal == nil {
		return VelocityJournalVerifier{}, ErrInvalidVelocityRecovery
	}
	return VelocityJournalVerifier{journalVerifier: i.journal}, nil
}

// JournalVerifier derives the native owner's configured primary verification
// view, preventing construction with a separately substituted journal reader.
// It grants no journal issuance; zero returns no verifier.
func (i VelocityNativeIssuer) JournalVerifier() (VelocityJournalVerifier, error) {
	if i.native == nil {
		return VelocityJournalVerifier{}, ErrInvalidVelocityRecovery
	}
	return VelocityJournalVerifier{journalVerifier: i.native.journal}, nil
}

// ValidateNative rejects mismatched/zero owners before adapter construction or
// IO. Matching capability identity proves only the intended composition pairing,
// never an external effect, primary lease or healthy state.
func (i VelocityJournalIssuer) ValidateNative(v VelocityNativeVerifier) error {
	if i.journal == nil || v.nativeVerifier == nil || v.nativeVerifier != i.journal.native {
		return ErrInvalidVelocityRecovery
	}
	return nil
}

// VelocityLeaseBinding is the primary owner's original acknowledged lease.
// Owner is sensitive fencing custody; only configured owned adapters may read
// this projection. ExpiresAt is original primary time, never locally refreshed.
type VelocityLeaseBinding struct {
	Tenant       string
	Namespace    [32]byte
	Epoch, Owner [16]byte
	Generation   uint64
	ExpiresAt    time.Time
}

// VelocityLease is immutable exact-issuer custody, not dispatch/health authority.
// It exposes no secret bindings or issuance methods; zero is invalid.
type VelocityLease struct{ state *velocityLease }
type velocityLease struct {
	issuer  *velocityJournalAuthority
	binding VelocityLeaseBinding
	check   func(context.Context) error
}

// Lease records an already acknowledged original primary lease. The concrete
// journal supplies a concurrent-safe, context-bounded checker for that exact
// receipt, never a transaction held across native IO. Construction performs no
// IO and grants no external effect or health permission.
func (i VelocityJournalIssuer) Lease(b VelocityLeaseBinding, check func(context.Context) error) (VelocityLease, error) {
	if i.journal == nil || !scopeID(b.Tenant) || b.Namespace == [32]byte{} || b.Epoch == [16]byte{} || b.Owner == [16]byte{} || b.Generation == 0 || !velocityWireTime(b.ExpiresAt) || check == nil {
		return VelocityLease{}, ErrInvalidVelocityRecovery
	}
	return VelocityLease{state: &velocityLease{issuer: i.journal, binding: b, check: check}}, nil
}

// Lease returns original fencing facts only for this verifier's exact issuer.
// This pure identity check does not establish current primary ownership.
func (v VelocityJournalVerifier) Lease(l VelocityLease) (VelocityLeaseBinding, error) {
	if v.journalVerifier == nil || l.state == nil || l.state.issuer != v.journalVerifier {
		return VelocityLeaseBinding{}, ErrInvalidVelocityRecovery
	}
	return l.state.binding, nil
}

// Check checks exact configured custody and current primary ownership under ctx.
// Nil context/zero/foreign handles deny before callbacks. Cancellation and
// deadlines are preserved; other checker errors are normalized and redacted.
func (v VelocityJournalVerifier) Check(ctx context.Context, l VelocityLease) error {
	if _, err := v.Lease(l); err != nil {
		return err
	}
	return checkVelocityLease(ctx, l)
}

func checkVelocityLease(ctx context.Context, l VelocityLease) error {
	if ctx == nil || l.state == nil {
		return ErrInvalidVelocityRecovery
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.state.check(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrVelocityRecoveryUnavailable
	}
	return ctx.Err()
}

// VelocityHistoryOutcome preserves original journal classification. Pending and
// Unknown remain unresolved; neither is noncommit or permission for a new debit.
type VelocityHistoryOutcome uint8

const (
	VelocityHistoryPending VelocityHistoryOutcome = iota + 1
	VelocityHistoryCommitted
	VelocityHistoryNotCommitted
	VelocityHistoryUnknown
)

// VelocityHistoryBinding is bounded authenticated original adapter data, not a
// replacement command. ID is canonical base64url journal identity; Attempt is
// the original keyed lookup digest. Targets retain original ordered aliases;
// snapshots retain original cumulative values and clocks in any dimension order.
// This projection grants no effect/issuance authority and omits raw attempts.
type VelocityHistoryBinding struct {
	ID                     string
	Position               int64
	Tenant                 string
	Namespace, Attempt     [32]byte
	Fingerprint            string
	Operation              Action
	Phase                  Phase
	PolicyVersion          uint64
	PreparedAt, RecordedAt time.Time
	Window                 time.Duration
	Limit                  uint64
	Outcome                VelocityHistoryOutcome
	Targets                []CounterTarget
	Snapshot               []Counter
}

// VelocityHistory is immutable original custody bound to one exact lease.
// It exposes no projection or issuance methods; zero is invalid.
type VelocityHistory struct{ state *velocityHistory }
type velocityHistory struct {
	lease   *velocityLease
	binding VelocityHistoryBinding
}

// History copies already authenticated original facts after the concrete
// journal's current SQL/seal/lease checks. It performs no IO or time sampling.
// Structural projections and foreign lease issuers cannot become configured
// native acknowledgements; admission checks remain each adapter's responsibility.
func (i VelocityJournalIssuer) History(l VelocityLease, b VelocityHistoryBinding) (VelocityHistory, error) {
	if i.journal == nil || l.state == nil || l.state.issuer != i.journal || !validVelocityHistory(l.state.binding, b) {
		return VelocityHistory{}, ErrInvalidVelocityRecovery
	}
	return VelocityHistory{state: &velocityHistory{lease: l.state, binding: cloneVelocityHistory(b)}}, nil
}

// History checks exact configured custody and current primary ownership, then
// returns an independent original binding. Returned slices cannot change custody.
func (v VelocityJournalVerifier) History(ctx context.Context, l VelocityLease, h VelocityHistory) (VelocityHistoryBinding, error) {
	if v.journalVerifier == nil || l.state == nil || h.state == nil || l.state.issuer != v.journalVerifier || h.state.lease != l.state {
		return VelocityHistoryBinding{}, ErrInvalidVelocityRecovery
	}
	if err := checkVelocityLease(ctx, l); err != nil {
		return VelocityHistoryBinding{}, err
	}
	return cloneVelocityHistory(h.state.binding), nil
}

// VelocityAcknowledgement is attributable native-owner custody of one original
// terminal effect. It is not durable applied progress or healthy-state evidence.
// Only the separately retained configured native issuer can create it.
type VelocityAcknowledgement struct{ state *velocityAcknowledgement }
type velocityAcknowledgement struct {
	issuer  *velocityNativeAuthority
	history *velocityHistory
}

// Acknowledge is called by the configured concrete native adapter only after
// its exact fenced effect acknowledgement. It rechecks current primary custody;
// pending/unknown history and canceled/expired/superseded ownership deny. It
// observes no IO itself: exposing this issuer to ordinary callers is unsafe.
func (i VelocityNativeIssuer) Acknowledge(ctx context.Context, l VelocityLease, h VelocityHistory) (VelocityAcknowledgement, error) {
	if i.native == nil {
		return VelocityAcknowledgement{}, ErrInvalidVelocityRecovery
	}
	v := VelocityJournalVerifier{journalVerifier: i.native.journal}
	b, err := v.History(ctx, l, h)
	if err != nil {
		return VelocityAcknowledgement{}, err
	}
	if b.Outcome != VelocityHistoryCommitted && b.Outcome != VelocityHistoryNotCommitted {
		return VelocityAcknowledgement{}, ErrVelocityRecoveryUnavailable
	}
	return VelocityAcknowledgement{state: &velocityAcknowledgement{issuer: i.native, history: h.state}}, nil
}

// Applied verifies exactly the configured native issuer and current original
// lease, then returns copied facts for independent primary authentication and
// ordered persistence. This method cannot itself advance progress or health.
func (v VelocityNativeVerifier) Applied(ctx context.Context, l VelocityLease, a VelocityAcknowledgement) (VelocityHistoryBinding, error) {
	if v.nativeVerifier == nil || a.state == nil || a.state.issuer != v.nativeVerifier {
		return VelocityHistoryBinding{}, ErrInvalidVelocityRecovery
	}
	return (VelocityJournalVerifier{journalVerifier: v.nativeVerifier.journal}).History(ctx, l, VelocityHistory{state: a.state.history})
}

func validVelocityHistory(l VelocityLeaseBinding, b VelocityHistoryBinding) bool {
	if b.Tenant != l.Tenant || b.Namespace != l.Namespace || !velocityRecordID(b.ID) || !lowerHexFingerprint(b.Fingerprint) || b.Attempt == [32]byte{} || b.Position <= 0 || !scopeID(string(b.Operation)) || (b.Phase != BeforeCredential && b.Phase != BeforeReturn) || b.PolicyVersion == 0 || !velocityWireTime(b.PreparedAt) || !velocityWireTime(b.RecordedAt) || b.RecordedAt.Before(b.PreparedAt) || b.Window <= 0 || b.Window > time.Hour || b.Window%time.Microsecond != 0 || b.Limit == 0 || b.Limit > 120 || b.Outcome < VelocityHistoryPending || b.Outcome > VelocityHistoryUnknown || len(b.Targets) < 1 || len(b.Targets) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, target := range b.Targets {
		kind := string(target.Dimension)
		if !scopeID(kind) || len(kind) > 64 || seen[kind] || len(target.Keys) < 1 || len(target.Keys) > 4 {
			return false
		}
		seen[kind] = true
		for rank, key := range target.Keys {
			if key.Version == 0 || len(key.Encoded) < 1 || len(key.Encoded) > 64 || rank > 0 && target.Keys[rank-1].Version <= key.Version {
				return false
			}
		}
	}
	if b.Outcome != VelocityHistoryCommitted {
		return len(b.Snapshot) == 0
	}
	if len(b.Snapshot) != len(b.Targets) {
		return false
	}
	observed := map[string]bool{}
	for rank, c := range b.Snapshot {
		if !seen[c.Kind] || observed[c.Kind] || c.Value == 0 || c.Value > 9007199254740991 || !velocityWireTime(c.ObservedAt) || !velocityWireTime(c.WindowStartedAt) || !velocityWireTime(c.WindowExpiresAt) || c.WindowExpiresAt.Sub(c.WindowStartedAt) != b.Window || c.ObservedAt.Before(c.WindowStartedAt) || !c.ObservedAt.Before(c.WindowExpiresAt) || rank > 0 && !c.ObservedAt.Equal(b.Snapshot[0].ObservedAt) {
			return false
		}
		observed[c.Kind] = true
	}
	return true
}
func cloneVelocityHistory(b VelocityHistoryBinding) VelocityHistoryBinding {
	b.Targets = slices.Clone(b.Targets)
	for i := range b.Targets {
		b.Targets[i].Keys = slices.Clone(b.Targets[i].Keys)
	}
	b.Snapshot = slices.Clone(b.Snapshot)
	return b
}
func velocityRecordID(v string) bool {
	if len(v) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(decoded) == 32
}
func lowerHexFingerprint(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := range len(v) {
		if !(v[i] >= '0' && v[i] <= '9') && !(v[i] >= 'a' && v[i] <= 'f') {
			return false
		}
	}
	return true
}
func velocityWireTime(v time.Time) bool {
	return v.UnixMicro() > 0 && v.UnixMicro() <= 9007199254740991 && v.Equal(time.UnixMicro(v.UnixMicro()))
}

func velocityRedacted(s fmt.State)                           { _, _ = io.WriteString(s, "risk.velocityRecovery(redacted)") }
func (VelocityJournalIssuer) Format(s fmt.State, _ rune)     { velocityRedacted(s) }
func (VelocityJournalVerifier) Format(s fmt.State, _ rune)   { velocityRedacted(s) }
func (VelocityNativeIssuer) Format(s fmt.State, _ rune)      { velocityRedacted(s) }
func (VelocityNativeVerifier) Format(s fmt.State, _ rune)    { velocityRedacted(s) }
func (VelocityLease) Format(s fmt.State, _ rune)             { velocityRedacted(s) }
func (VelocityLeaseBinding) Format(s fmt.State, _ rune)      { velocityRedacted(s) }
func (VelocityHistory) Format(s fmt.State, _ rune)           { velocityRedacted(s) }
func (VelocityHistoryBinding) Format(s fmt.State, _ rune)    { velocityRedacted(s) }
func (VelocityAcknowledgement) Format(s fmt.State, _ rune)   { velocityRedacted(s) }
func (VelocityJournalIssuer) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (VelocityJournalVerifier) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityNativeIssuer) MarshalJSON() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (VelocityNativeVerifier) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (VelocityLease) MarshalJSON() ([]byte, error)           { return nil, ErrSensitiveSerialization }
func (VelocityLeaseBinding) MarshalJSON() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (VelocityHistory) MarshalJSON() ([]byte, error)         { return nil, ErrSensitiveSerialization }
func (VelocityHistoryBinding) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (VelocityAcknowledgement) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityJournalIssuer) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (VelocityJournalVerifier) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityNativeIssuer) MarshalText() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (VelocityNativeVerifier) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (VelocityLease) MarshalText() ([]byte, error)           { return nil, ErrSensitiveSerialization }
func (VelocityLeaseBinding) MarshalText() ([]byte, error)    { return nil, ErrSensitiveSerialization }
func (VelocityHistory) MarshalText() ([]byte, error)         { return nil, ErrSensitiveSerialization }
func (VelocityHistoryBinding) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (VelocityAcknowledgement) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
