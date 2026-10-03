package risk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"time"
)

var (
	// ErrInvalidCounterCommand identifies invalid scope, dimensions or dispatch ownership.
	ErrInvalidCounterCommand = errors.New("risk: invalid counter command")
	// ErrInvalidCounterResult identifies incomplete or inconsistent adapter declarations.
	ErrInvalidCounterResult = errors.New("risk: invalid counter result")
	// ErrUnsupportedCounterPhase prevents independent mutation of protected-command counters.
	ErrUnsupportedCounterPhase = errors.New("risk: unsupported counter phase")
	// ErrSensitiveSerialization prevents accidental export of sensitive projections.
	ErrSensitiveSerialization = errors.New("risk: sensitive serialization forbidden")
)

// Subject contains only trusted server-resolved, canonical dimension values.
// Exact profile dimensions must be present and all other fields empty. Network
// is parsed as one bounded full IPv4/IPv6 address, never a subnet or zone. The
// caller owns identifier normalization and trusted-proxy/device provenance;
// accepting this structural value does not establish either authority.
type Subject struct {
	Network, Device, IdentifierDigest string
	User, Session, Actor, Resource    string
}

func (Subject) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "risk.Subject(redacted)") }
func (Subject) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (Subject) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CounterDigestKey owns an immutable copy of versioned HMAC key material. Zero
// is invalid; copies share private immutable storage. Go offers no guaranteed
// memory erasure. Automatic formatting/serialization never exports the secret.
type CounterDigestKey struct {
	version uint32
	secret  []byte
}

// NewCounterDigestKey accepts a positive version and 32..128 secret bytes. It
// copies input and never retains caller-owned mutable storage.
func NewCounterDigestKey(version uint32, secret []byte) (CounterDigestKey, error) {
	if version == 0 || len(secret) < 32 || len(secret) > 128 {
		return CounterDigestKey{}, ErrInvalidPolicy
	}
	return CounterDigestKey{version: version, secret: slices.Clone(secret)}, nil
}
func (CounterDigestKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterDigestKey(redacted)")
}
func (CounterDigestKey) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CounterDigestKey) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CounterKey is an adapter-only storage projection, not a bearer or risk proof.
// Encoded is bounded to 64 bytes and contains a versioned keyed digest only.
type CounterKey struct {
	Version uint32
	Encoded string
}

func (CounterKey) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "risk.CounterKey(redacted)") }

// CounterTarget names one logical counter and its retained digest-version
// aliases. Aliases MUST be reconciled as one logical mutation, not summed or
// treated as independent new windows. Stores must validate the complete key set
// against their authoritative rotation history before mutation.
type CounterTarget struct {
	Dimension Dimension
	Keys      []CounterKey
}

func (CounterTarget) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterTarget(redacted)")
}

// CounterBinding is the owned adapter projection. PreparedAt bounds admission,
// not storage time or replay identity. The fingerprint fixes scope, phase,
// policy and every dimension key; adapters preserve original recorded outcomes.
// Raw dimension values and secret keys are absent. This is not public HTTP data.
type CounterBinding struct {
	Tenant        string
	Operation     Action
	Attempt       string
	Phase         Phase
	PolicyVersion uint64
	PreparedAt    time.Time
	Window        time.Duration
	Limit         uint64
	Fingerprint   string
	Targets       []CounterTarget
}

func (CounterBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterBinding(redacted)")
}

// CounterCommand is opaque, immutable and bound to its preparing ephemeral
// coordinator or command-owned policy. These authority lanes are disjoint;
// storage projections cannot confer dispatch authority. It declares exactly
// one attempt, not an arbitrary increment.
type CounterCommand struct{ state *counterCommand }
type counterCommand struct {
	owner        *counterCoordinator
	commandOwner *commandCounterPolicy
	binding      CounterBinding
	profile      Profile
}

func (CounterCommand) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterCommand(redacted)")
}
func (CounterCommand) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CounterCommand) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Bindings returns independent slice projections for the named storage adapter.
// Zero returns an empty invalid projection; projection is never authority.
func (c CounterCommand) Bindings() CounterBinding {
	if c.state == nil {
		return CounterBinding{}
	}
	b := c.state.binding
	b.Targets = slices.Clone(b.Targets)
	for i := range b.Targets {
		b.Targets[i].Keys = slices.Clone(b.Targets[i].Keys)
	}
	return b
}

// Counter is an attributable post-mutation snapshot, not a before-state hint.
// Value zero is valid. Stores count logical attempts without wrapping uint64,
// preserve original window boundaries and use authoritative storage time.
// ObservedAt is the original authoritative read beginning, preserved through
// replay and promotion; returning a stored snapshot must never refresh it.
type Counter struct {
	Kind                             string
	Value                            uint64
	ObservedAt                       time.Time
	WindowStartedAt, WindowExpiresAt time.Time
}

// CounterOutcome distinguishes an authoritative complete mutation, proven no
// mutation and ambiguity. Zero is invalid. Unknown permits no automatic retry.
type CounterOutcome uint8

const (
	CounterCommitted CounterOutcome = iota + 1
	CounterNotCommitted
	CounterUnknown
)

// CounterResult is an immutable adapter declaration for one exact command.
// It does not authenticate the store: only a configured owned adapter may
// supply it. Construction/structural validation grants no credential authority.
type CounterResult struct{ state *counterResult }
type counterResult struct {
	fingerprint string
	outcome     CounterOutcome
	snapshot    []Counter
}

func (CounterResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterResult(redacted)")
}

// NewCounterResult admits the exact complete post-mutation snapshot, or an
// explicit noncommit/unknown result with no snapshot. Duplicate, missing,
// foreign kinds and invalid window bounds return zero and a redacted error.
// Current freshness is checked separately when the result is consumed.
// For command-owned counters, open-Work SQL is provisional: the native adapter
// may declare CounterCommitted only after the owning coordinator proves commit.
func NewCounterResult(command CounterCommand, outcome CounterOutcome, snapshot []Counter) (CounterResult, error) {
	if command.state == nil || outcome < CounterCommitted || outcome > CounterUnknown {
		return CounterResult{}, ErrInvalidCounterResult
	}
	b := command.state.binding
	if outcome != CounterCommitted {
		if len(snapshot) != 0 {
			return CounterResult{}, ErrInvalidCounterResult
		}
	} else {
		if len(snapshot) != len(b.Targets) {
			return CounterResult{}, ErrInvalidCounterResult
		}
		seen := make(map[string]bool, len(snapshot))
		for _, counter := range snapshot {
			if len(counter.Kind) > 64 || seen[counter.Kind] || !validTime(counter.ObservedAt) || !validTime(counter.WindowStartedAt) || !validTime(counter.WindowExpiresAt) || !counter.WindowExpiresAt.After(counter.WindowStartedAt) || counter.WindowExpiresAt.Sub(counter.WindowStartedAt) > b.Window {
				return CounterResult{}, ErrInvalidCounterResult
			}
			found := false
			for _, target := range b.Targets {
				if counter.Kind == string(target.Dimension) {
					found = true
				}
			}
			if !found {
				return CounterResult{}, ErrInvalidCounterResult
			}
			seen[counter.Kind] = true
		}
	}
	return CounterResult{state: &counterResult{fingerprint: b.Fingerprint, outcome: outcome, snapshot: slices.Clone(snapshot)}}, nil
}

// CounterStore is the sole configured ephemeral mutation authority. Mutate
// must atomically mutate the exact logical command and return its original
// post-state for a same-fingerprint replay. It must reject foreign replays,
// incomplete rotation aliases and unhealthy/lost epochs. PostgreSQL's existing
// journal owns recovery; Valkey owns only the ephemeral windows. Errors with no
// complete direct result mean unknown, never noncommit. Stores must honor bounded
// contexts and close resources; the core never retries or starts a goroutine.
type CounterStore interface {
	Mutate(context.Context, CounterCommand) (CounterResult, error)
}

// CounterCoordinatorConfig pins explicit policy, owned ephemeral store, clock,
// deadline and newest-first retained digest keys. At most four versions are
// supported. All unretired active-window keys must be supplied; the adapter
// must reject removal not proven by durable rotation/retirement authority.
// No lockout or journal authority can be configured through this counter path.
type CounterCoordinatorConfig struct {
	Policy  Policy
	Store   CounterStore
	Clock   func() time.Time
	Timeout time.Duration
	Keys    []CounterDigestKey
}

// CounterCoordinator owns phase admission, key derivation and post-state
// normalization, not counter algorithms/storage, lockouts, audit or journal
// recovery. It is immutable and concurrency safe when its store/clock are.
// It starts no goroutine and needs no shutdown. Zero is invalid.
type CounterCoordinator struct{ state *counterCoordinator }
type counterCoordinator struct {
	policy  Policy
	store   CounterStore
	clock   func() time.Time
	timeout time.Duration
	keys    []CounterDigestKey
}

// NewCounterCoordinator validates bounded configuration without store access.
// The key list is copied; secret key values are already independently owned.
func NewCounterCoordinator(c CounterCoordinatorConfig) (CounterCoordinator, error) {
	if c.Policy.state == nil || c.Store == nil || c.Clock == nil || c.Timeout <= 0 || c.Timeout > time.Minute || len(c.Keys) == 0 || len(c.Keys) > 4 {
		return CounterCoordinator{}, ErrInvalidPolicy
	}
	// Reflection is limited to rejecting typed nil interfaces; it does not wire
	// dependencies, discover stores or select state ownership.
	v := reflect.ValueOf(c.Store)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return CounterCoordinator{}, ErrInvalidPolicy
		}
	}
	for i, key := range c.Keys {
		if key.version == 0 || len(key.secret) < 32 || len(key.secret) > 128 || (i > 0 && c.Keys[i-1].version <= key.version) {
			return CounterCoordinator{}, ErrInvalidPolicy
		}
	}
	return CounterCoordinator{state: &counterCoordinator{policy: c.Policy, store: c.Store, clock: c.Clock, timeout: c.Timeout, keys: slices.Clone(c.Keys)}}, nil
}

// Prepare freezes the exact operation, policy, phase and scoped keyed targets
// without store access. Request time/factor flags are ignored. Only the two
// non-transactional phases execute here; reserve_with_owning_command requires
// the later shared-Work participant and fails closed, never an independent
// mutation. Unsupported/extra dimensions or invalid clocks return zero.
func (c CounterCoordinator) Prepare(scope Context, subject Subject, phase Phase) (CounterCommand, error) {
	a, err := c.admitScope(scope, phase)
	if err != nil {
		return CounterCommand{}, err
	}
	now := c.state.clock()
	if !validTime(now) {
		return CounterCommand{}, ErrInvalidCounterCommand
	}
	return c.prepareAdmitted(scope, subject, phase, a, now)
}

// Intent reconstruction needs the same closed scope admission but must not
// sample the independently configured mutation clock inside a transaction.
func (c CounterCoordinator) admitScope(scope Context, phase Phase) (Admission, error) {
	if c.state == nil {
		return Admission{}, ErrInvalidPolicy
	}
	a, err := c.state.policy.Admit(scope.Operation)
	if err != nil {
		return Admission{}, err
	}
	if a.Preflight != "" || phase != a.Profile.Phase || !scopeID(scope.Tenant) || !scopeID(scope.Attempt) {
		return Admission{}, ErrInvalidCounterCommand
	}
	if phase == ReserveWithCommand {
		return Admission{}, ErrUnsupportedCounterPhase
	}
	return a, nil
}

func (c CounterCoordinator) prepareAdmitted(scope Context, subject Subject, phase Phase, a Admission, now time.Time) (CounterCommand, error) {
	command, err := prepareCounter(scope, subject, phase, a, now, c.state.keys, false)
	if err != nil {
		return CounterCommand{}, err
	}
	command.state.owner = c.state
	return command, nil
}

func prepareCounter(scope Context, subject Subject, phase Phase, a Admission, now time.Time, keys []CounterDigestKey, protected bool) (CounterCommand, error) {
	values, err := counterDimensions(subject, scope.Tenant, a.Profile.Dimensions)
	if err != nil {
		return CounterCommand{}, err
	}
	b := CounterBinding{Tenant: scope.Tenant, Operation: scope.Operation, Attempt: scope.Attempt, Phase: phase, PolicyVersion: a.PolicyVersion, PreparedAt: now, Window: a.Profile.Window, Limit: a.Profile.Limit}
	keyDomain, commandDomain, prefix := "identity-risk-counter-key-v1", "identity-risk-counter-command-v1", "rv1:"
	if protected {
		keyDomain, commandDomain, prefix = "identity-risk-command-counter-key-v1", "identity-risk-command-counter-command-v1", "rc1:"
	}
	for _, dimension := range a.Profile.Dimensions {
		target := CounterTarget{Dimension: dimension}
		for _, key := range keys {
			digest := counterMAC(key, keyDomain, []string{strconv.FormatUint(uint64(key.version), 10), scope.Tenant, string(scope.Operation), string(dimension), values[dimension]})
			target.Keys = append(target.Keys, CounterKey{Version: key.version, Encoded: prefix + strconv.FormatUint(uint64(key.version), 10) + ":" + base64.RawURLEncoding.EncodeToString(digest)})
		}
		b.Targets = append(b.Targets, target)
	}
	fields := []string{scope.Tenant, string(scope.Operation), scope.Attempt, string(phase), strconv.FormatUint(a.PolicyVersion, 10), strconv.FormatInt(int64(b.Window), 10), strconv.FormatUint(b.Limit, 10)}
	for _, target := range b.Targets {
		fields = append(fields, string(target.Dimension))
		for _, key := range target.Keys {
			fields = append(fields, key.Encoded)
		}
	}
	b.Fingerprint = hex.EncodeToString(counterMAC(keys[0], commandDomain, fields))
	return CounterCommand{state: &counterCommand{binding: b, profile: a.Profile}}, nil
}

func counterDimensions(s Subject, tenant string, dimensions []Dimension) (map[Dimension]string, error) {
	all := map[Dimension]string{TenantDimension: tenant, DeviceDimension: s.Device, IdentifierDimension: s.IdentifierDigest, SubjectDimension: s.User, SessionDimension: s.Session, ActorDimension: s.Actor, ResourceDimension: s.Resource}
	if s.Network != "" {
		if len(s.Network) > 45 {
			return nil, ErrInvalidCounterCommand
		}
		address, err := netip.ParseAddr(s.Network)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return nil, ErrInvalidCounterCommand
		}
		all[NetworkDimension] = address.Unmap().String()
	}
	if slices.Contains(dimensions, SubjectOrNetworkDimension) {
		if (s.User == "") == (s.Network == "") {
			return nil, ErrInvalidCounterCommand
		}
		if s.User != "" {
			all[SubjectOrNetworkDimension] = "subject:" + s.User
			delete(all, SubjectDimension)
		} else {
			all[SubjectOrNetworkDimension] = "network:" + all[NetworkDimension]
			delete(all, NetworkDimension)
		}
	}
	// Check the required set separately: an absent map entry is not an empty
	// optional dimension and must never derive a shared empty-value counter key.
	for _, dimension := range dimensions {
		if !scopeID(all[dimension]) {
			return nil, ErrInvalidCounterCommand
		}
	}
	for dimension, value := range all {
		used := slices.Contains(dimensions, dimension)
		if (!used && value != "") || (used && !scopeID(value)) {
			return nil, ErrInvalidCounterCommand
		}
		if used && dimension == IdentifierDimension {
			if len(value) != 64 {
				return nil, ErrInvalidCounterCommand
			}
			for _, b := range []byte(value) {
				if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
					return nil, ErrInvalidCounterCommand
				}
			}
		}
	}
	return all, nil
}

func counterMAC(key CounterDigestKey, domain string, fields []string) []byte {
	m := hmac.New(sha256.New, key.secret)
	writeCounterField(m, domain)
	for _, field := range fields {
		writeCounterField(m, field)
	}
	return m.Sum(nil)
}
func writeCounterField(m hash.Hash, field string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	_, _ = m.Write(size[:])
	_, _ = io.WriteString(m, field)
}

// CounterEvaluation retains explicit commit state beside a normalized signal.
// Unknown/noncommit never contain positive facts or fabricated retry-after.
// A committed but cancelled/stale result retains its commit classification,
// with an unavailable signal; this does not erase a known external mutation.
type CounterEvaluation struct {
	Outcome CounterOutcome
	Signal  Signal
	result  CounterResult
}

func (CounterEvaluation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CounterEvaluation(redacted)")
}

// Mutate dispatches the exact prepared command once and consumes only a complete
// attributable post-state. Limit N permits N attempts; count>N yields the fixed
// threshold action. Unknown is unavailable, not retried. Same-command replay
// and rotation/epoch continuity belong to the injected adapter and journal.
// It is not a risk decision, evidence issuance, audit or permission to execute.
func (c CounterCoordinator) Mutate(ctx context.Context, command CounterCommand) (CounterEvaluation, error) {
	if c.state == nil {
		return CounterEvaluation{}, ErrInvalidPolicy
	}
	if ctx == nil || command.state == nil || command.state.commandOwner != nil || command.state.owner != c.state {
		return CounterEvaluation{}, ErrInvalidCounterCommand
	}
	if err := ctx.Err(); err != nil {
		return CounterEvaluation{}, err
	}
	b, p := command.state.binding, command.state.profile
	start := c.state.clock()
	if !validTime(start) || start.Before(b.PreparedAt) || !start.Before(b.PreparedAt.Add(p.EvidenceTTL)) {
		return CounterEvaluation{}, ErrInvalidCounterCommand
	}
	bounded, cancel := context.WithTimeout(ctx, c.state.timeout)
	defer cancel()
	raw, readErr := c.state.store.Mutate(bounded, command)
	now := c.state.clock()
	result := CounterEvaluation{Outcome: CounterUnknown, Signal: Signal{Tenant: b.Tenant, Operation: b.Operation, Attempt: b.Attempt, Name: "velocity", State: SignalUnavailable, Trust: ServerVerified}}
	if raw.state == nil || raw.state.fingerprint != b.Fingerprint {
		return result, nil
	}
	result.Outcome, result.result = raw.state.outcome, raw
	if readErr != nil || result.Outcome != CounterCommitted {
		return result, nil
	}
	// A complete known mutation remains committed even when no positive signal
	// can be used after cancellation, timeout, backward clock or window expiry.
	if bounded.Err() != nil || evaluationTime(now, start, start, c.state.timeout) != nil {
		return result, nil
	}
	exceeded := false
	observed := now
	expires := start.Add(p.EvidenceTTL)
	for _, counter := range raw.state.snapshot {
		if counter.ObservedAt.After(now) || !counter.ObservedAt.Add(p.EvidenceTTL).After(now) || counter.WindowStartedAt.After(now) || !counter.WindowExpiresAt.After(now) {
			return result, nil
		}
		if counter.ObservedAt.Before(observed) {
			observed = counter.ObservedAt
		}
		if expiry := counter.ObservedAt.Add(p.EvidenceTTL); expiry.Before(expires) {
			expires = expiry
		}
		if counter.WindowExpiresAt.Before(expires) {
			expires = counter.WindowExpiresAt
		}
		if counter.Value > b.Limit {
			exceeded = true
		}
	}
	result.Signal.State, result.Signal.ObservedAt, result.Signal.ExpiresAt = SignalClean, observed, expires
	if exceeded {
		result.Signal.State = SignalDeny
		if p.ThresholdAction == Throttle {
			result.Signal.State, result.Signal.RetryAfter = SignalThrottle, counterRetryAfter(raw.state.snapshot, b.Limit, now, c.state.policy.state.limits.RetryAfterMax)
		}
	}
	return result, nil
}

// Retry metadata belongs to the decision instant, not the original observation.
// Recompute from immutable exceeded windows so later source work and configured
// clipping cannot extend a delay or renew the evidence interval.
func counterRetryAfter(snapshot []Counter, limit uint64, now time.Time, maximum time.Duration) time.Duration {
	remaining := time.Duration(0)
	for _, counter := range snapshot {
		if counter.Value > limit {
			remaining = max(remaining, counter.WindowExpiresAt.Sub(now))
		}
	}
	return min(remaining, maximum)
}
