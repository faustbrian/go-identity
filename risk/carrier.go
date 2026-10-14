package risk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrInvalidCarrierRequest rejects an incomplete or phase-mismatched binding.
	ErrInvalidCarrierRequest = errors.New("risk: invalid carrier request")
	// ErrInvalidCarrierAssessment rejects zero, denied, foreign or stale assessments.
	ErrInvalidCarrierAssessment = errors.New("risk: invalid carrier assessment")
	// ErrCarrierRecoveryDisabled denies phone recovery when startup has not enabled it.
	ErrCarrierRecoveryDisabled = errors.New("risk: carrier recovery disabled")
	// ErrCarrierEvaluationUnavailable rejects unusable clocks or evaluation budgets.
	ErrCarrierEvaluationUnavailable = errors.New("risk: carrier evaluation unavailable")
)

// CarrierKind is the closed mandatory phone-recovery fact catalog. All three
// kinds must have distinct configured owners; zero and aliases are invalid.
type CarrierKind string

const (
	SIMSwap         CarrierKind = "sim-swap"
	NumberRecycling CarrierKind = "number-recycling"
	Carrier         CarrierKind = "carrier-risk"
)

// CarrierState is an attributable provider fact, never a recovery decision.
// Only Negative can contribute to a usable assessment. Zero/unknown values,
// missing facts and reader errors normalize to unavailable and deny.
type CarrierState uint8

const (
	CarrierNegative CarrierState = iota + 1
	CarrierPositive
	CarrierUnknown
	CarrierUnavailable
)

// PhoneRecoveryScope is preparatory trusted server workflow input. It is not
// the canonical Service's PhoneRecoveryBinding contract; official composition
// must map that complete native command rather than treating these scalar
// projections as interchangeable typed identity or issuance authority. It contains
// no caller-selected purpose or provider result. Directory identifiers are
// already resolved and at most 128 safe ASCII bytes; preauth/attempt identifiers
// are 16..128 bytes. The number is already canonical, 8..16 E.164 syntax bytes.
// Structural validation proves neither number assignment nor phone ownership;
// those remain the phone workflow's normalization and authoritative-state work.
// Never deserialize transport input directly into this value or log/export it.
type PhoneRecoveryScope struct {
	Tenant, Subject                              string
	RecoveryOperation                            Action
	CanonicalNumber, PreAuthTransaction, Attempt string
	PolicyVersion                                uint64
}

func (PhoneRecoveryScope) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PhoneRecoveryScope(redacted)")
}
func (PhoneRecoveryScope) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (PhoneRecoveryScope) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CarrierRequest binds one issuing phase to its parent recovery operation.
// Only initiation/request and completion/complete pairs are accepted. The
// purpose is derived inside risk and has no caller override field. Copies
// contain immutable scalars; callers must not mutate input concurrently.
type CarrierRequest struct {
	Binding PhoneRecoveryScope
	Phase   IssuancePhase
}

func (CarrierRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CarrierRequest(redacted)")
}
func (CarrierRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CarrierRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CarrierObservation is scope-attributable output from a configured server-owned
// subset reader, not the canonical aggregate CarrierFact protocol contract.
// Binding/phase/kind/provider version must match its exact request and startup
// owner. ObservedAt is the original authoritative read beginning, not cache
// retrieval time; replay, promotion and retries cannot reset it. ExpiresAt is
// exclusive, after observation and at most two minutes later. Raw provider
// bodies, decision overrides and secrets have no representation here.
type CarrierObservation struct {
	Binding               PhoneRecoveryScope
	Phase                 IssuancePhase
	Kind                  CarrierKind
	State                 CarrierState
	ProviderVersion       string
	ObservedAt, ExpiresAt time.Time
}

func (CarrierObservation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CarrierObservation(redacted)")
}
func (CarrierObservation) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CarrierObservation) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CarrierSource pins one read-only provider owner and its exact configuration
// version. Read must honor its bounded context, clean resources and support
// concurrent requests. It cannot issue evidence, mutate counters or credentials,
// or return caller-provided facts. Official provider adapters remain required;
// configuring a callback here does not prove provider interoperability.
type CarrierSource struct {
	Kind    CarrierKind
	Version string
	Timeout time.Duration
	Read    func(context.Context, CarrierRequest) (CarrierObservation, error)
}

// CarrierEvaluatorConfig is startup-only. Enabled is the sole enablement switch;
// the zero config constructs a disabled evaluator. Disabled configurations
// contain no other fields. Enabling requires a positive policy version, explicit
// 1s..2m lifetime, trusted UTC clock, 0<Timeout<=1m and exactly three owners.
// Source deadlines cannot exceed the total deadline. Configuration is copied;
// callers must not replace or mutate callbacks after construction.
type CarrierEvaluatorConfig struct {
	Enabled       bool
	PolicyVersion uint64
	Lifetime      time.Duration
	Clock         func() time.Time
	Timeout       time.Duration
	Sources       []CarrierSource
}

// CarrierEvaluator owns the mandatory carrier subset, not the complete risk
// service. It starts no goroutine, has no shutdown and holds no lock across IO.
// It is immutable/concurrent-safe when its readers and clock are. Zero is invalid.
// A usable assessment cannot replace full operation risk/counters, durable
// RiskEvidence issuance/consumption, OTP/capability or an independent factor.
type CarrierEvaluator struct{ state *carrierEvaluator }
type carrierEvaluator struct {
	enabled             bool
	version             uint64
	lifetime, timeLimit time.Duration
	clock               func() time.Time
	sources             [3]CarrierSource
}

// NewCarrierEvaluator validates ownership and bounds without clock/provider IO.
// Invalid/overlapping/missing ownership returns zero and ErrInvalidPolicy.
func NewCarrierEvaluator(c CarrierEvaluatorConfig) (CarrierEvaluator, error) {
	if !c.Enabled {
		if c.PolicyVersion != 0 || c.Lifetime != 0 || c.Clock != nil || c.Timeout != 0 || len(c.Sources) != 0 {
			return CarrierEvaluator{}, ErrInvalidPolicy
		}
		return CarrierEvaluator{state: &carrierEvaluator{}}, nil
	}
	if c.PolicyVersion == 0 || c.Lifetime < time.Second || c.Lifetime > 2*time.Minute || c.Clock == nil || c.Timeout <= 0 || c.Timeout > time.Minute || len(c.Sources) != 3 {
		return CarrierEvaluator{}, ErrInvalidPolicy
	}
	s := &carrierEvaluator{enabled: true, version: c.PolicyVersion, lifetime: c.Lifetime, timeLimit: c.Timeout, clock: c.Clock}
	for _, source := range c.Sources {
		i := carrierIndex(source.Kind)
		if i < 0 || s.sources[i].Read != nil || !scopeID(source.Version) || len(source.Version) > 64 || source.Timeout <= 0 || source.Timeout > c.Timeout || source.Read == nil {
			return CarrierEvaluator{}, ErrInvalidPolicy
		}
		s.sources[i] = source
	}
	return CarrierEvaluator{state: s}, nil
}

func carrierIndex(k CarrierKind) int {
	switch k {
	case SIMSwap:
		return 0
	case NumberRecycling:
		return 1
	case Carrier:
		return 2
	default:
		return -1
	}
}

// CarrierMetadata is the safe assessment subset. Purpose is derived from phase;
// denied results have zero times. No phone/provider facts or correlation IDs are
// exposed. These fields are data, not mutable authority or permission to recover.
type CarrierMetadata struct {
	Decision              DecisionAction
	Phase                 IssuancePhase
	Purpose               string
	PolicyVersion         uint64
	ObservedAt, ExpiresAt time.Time
}

// CarrierAssessment is an immutable, evaluator-bound internal issuance input,
// never a bearer, durable evidence row or authentication proof. It cannot be
// constructed from metadata or request facts. Copies preserve original time.
// The later risk issuer must validate against its configured expected evaluator,
// then complete full risk/counter checks and the durable issuance transaction.
type CarrierAssessment struct{ state *carrierAssessment }
type carrierAssessment struct {
	owner    *carrierEvaluator
	request  CarrierRequest
	metadata CarrierMetadata
	finished time.Time
	facts    [3]CarrierObservation
}

func (CarrierAssessment) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CarrierAssessment(redacted)")
}
func (CarrierAssessment) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CarrierAssessment) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Metadata returns safe scalar data; zero returns an invalid empty projection.
func (a CarrierAssessment) Metadata() CarrierMetadata {
	if a.state == nil {
		return CarrierMetadata{}
	}
	return a.state.metadata
}

// Validate rejects denied/zero/foreign, different-phase/binding and stale values.
// The expected evaluator comes from trusted issuer configuration, never request
// selection. Expiry is exclusive; validation performs no IO or freshness reset.
// Success admits only the carrier subset, not one-use recovery authority.
func (a CarrierAssessment) Validate(expected CarrierEvaluator, request CarrierRequest, now time.Time) error {
	if a.state == nil || expected.state == nil || a.state.owner != expected.state || a.state.request != request || a.state.metadata.Decision != Allow || !validTime(now) || now.Before(a.state.finished) || !now.Before(a.state.metadata.ExpiresAt) {
		return ErrInvalidCarrierAssessment
	}
	return nil
}

// Assess evaluates every mandatory reader once in fixed kind order. Errors,
// malformed/foreign/positive/unknown/unavailable facts deny, with no retry or
// partial clean substitution. Original freshness is rechecked after all reads.
// Cancellation or an unusable clock/total budget returns zero. Non-cooperative
// readers cannot be forcibly interrupted, but their late facts cannot allow.
// An Allow assessment does not issue a reference or authorize a protected effect.
func (e CarrierEvaluator) Assess(ctx context.Context, r CarrierRequest) (CarrierAssessment, error) {
	if e.state == nil {
		return CarrierAssessment{}, ErrInvalidPolicy
	}
	if !e.state.enabled {
		return CarrierAssessment{}, ErrCarrierRecoveryDisabled
	}
	if ctx == nil {
		return CarrierAssessment{}, ErrInvalidCarrierRequest
	}
	if err := ctx.Err(); err != nil {
		return CarrierAssessment{}, err
	}
	purpose, ok := carrierPurpose(r, e.state.version)
	if !ok {
		return CarrierAssessment{}, ErrInvalidCarrierRequest
	}
	start := e.state.clock()
	if !validTime(start) {
		return CarrierAssessment{}, ErrCarrierEvaluationUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, e.state.timeLimit)
	defer cancel()
	state := &carrierAssessment{owner: e.state, request: r, metadata: CarrierMetadata{Decision: Allow, Phase: r.Phase, Purpose: purpose, PolicyVersion: e.state.version, ObservedAt: start, ExpiresAt: start.Add(e.state.lifetime)}}
	last := start
	for i, source := range e.state.sources {
		readStarted := last
		child, stop := context.WithTimeout(bounded, source.Timeout)
		fact, readErr := source.Read(child, r)
		childErr := child.Err()
		stop()
		if err := bounded.Err(); err != nil {
			return CarrierAssessment{}, err
		}
		now := e.state.clock()
		if evaluationTime(now, last, start, e.state.timeLimit) != nil {
			return CarrierAssessment{}, ErrCarrierEvaluationUnavailable
		}
		last = now
		if readErr != nil || childErr != nil || now.Sub(readStarted) >= source.Timeout || !validCarrierFact(fact, r, source, now) {
			fact = CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: source.Kind, State: CarrierUnavailable, ProviderVersion: source.Version}
		}
		state.facts[i] = fact
	}
	state.finished = last
	for _, fact := range state.facts {
		if fact.State != CarrierNegative || !validTime(fact.ObservedAt) || !fact.ExpiresAt.After(last) || !fact.ObservedAt.Add(e.state.lifetime).After(last) {
			state.metadata.Decision = Deny
			continue
		}
		if fact.ObservedAt.Before(state.metadata.ObservedAt) {
			state.metadata.ObservedAt = fact.ObservedAt
		}
		if fact.ExpiresAt.Before(state.metadata.ExpiresAt) {
			state.metadata.ExpiresAt = fact.ExpiresAt
		}
		if expiry := fact.ObservedAt.Add(e.state.lifetime); expiry.Before(state.metadata.ExpiresAt) {
			state.metadata.ExpiresAt = expiry
		}
	}
	if state.metadata.Decision == Deny {
		state.metadata.ObservedAt = time.Time{}
		state.metadata.ExpiresAt = time.Time{}
	}
	return CarrierAssessment{state: state}, nil
}

func validCarrierFact(f CarrierObservation, r CarrierRequest, s CarrierSource, now time.Time) bool {
	return f.Binding == r.Binding && f.Phase == r.Phase && f.Kind == s.Kind && f.ProviderVersion == s.Version && f.State >= CarrierNegative && f.State <= CarrierUnavailable && validTime(f.ObservedAt) && validTime(f.ExpiresAt) && !f.ObservedAt.After(now) && f.ExpiresAt.After(now) && f.ExpiresAt.After(f.ObservedAt) && f.ExpiresAt.Sub(f.ObservedAt) <= 2*time.Minute
}

func carrierPurpose(r CarrierRequest, version uint64) (string, bool) {
	b := r.Binding
	if !scopeID(b.Tenant) || !scopeID(b.Subject) || !scopeID(b.PreAuthTransaction) || len(b.PreAuthTransaction) < 16 || !scopeID(b.Attempt) || len(b.Attempt) < 16 || b.PolicyVersion != version || !canonicalRecoveryNumber(b.CanonicalNumber) {
		return "", false
	}
	switch r.Phase {
	case PhoneResetInitiation:
		return "phone-password-reset-initiate", b.RecoveryOperation == "identity.phone.password-reset-request"
	case PhoneResetCompletion:
		return "phone-password-reset-complete", b.RecoveryOperation == "identity.phone.password-reset-complete"
	default:
		return "", false
	}
}

func canonicalRecoveryNumber(s string) bool {
	if len(s) < 8 || len(s) > 16 || s[0] != '+' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
