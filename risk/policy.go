// Package risk owns action-bound identity abuse policy. Assessments are data,
// never authentication, authorization or one-use evidence. Durable authorities
// and provider orchestration remain separately composed implementation work.
package risk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

var (
	// ErrInvalidPolicy rejects incomplete or contradictory deployment policy.
	ErrInvalidPolicy = errors.New("risk: invalid policy")
	// ErrInvalidAction rejects unlisted operations and aliases before signal access.
	ErrInvalidAction = errors.New("risk: invalid action")
	// ErrInvalidContext rejects incomplete or inconsistent trusted scope/time.
	ErrInvalidContext = errors.New("risk: invalid context")
	// ErrInvalidSignal rejects foreign, stale, duplicate or malformed signals.
	ErrInvalidSignal = errors.New("risk: invalid signal")
)

// Action is one exact canonical public operation ID, not a category or decision.
type Action string

// DecisionAction is closed; zero and "challenge"/"revoke" are invalid.
type DecisionAction string

const (
	// Allow is the weakest decision and grants no identity/credential authority.
	Allow DecisionAction = "allow"
	// Throttle postpones work using attributable bounded retry metadata.
	Throttle DecisionAction = "throttle"
	// StepUp requires an independently configured factor, not a risk bypass.
	StepUp DecisionAction = "step_up"
	// Deny is irreversible within this assessment; revocation is another owner.
	Deny DecisionAction = "deny"
)

// ProfileClass selects a closed canonical operation classification.
type ProfileClass uint8

const (
	// Authentication covers credential/provider admission.
	Authentication ProfileClass = iota + 1
	// CredentialMutation covers protected account/credential changes.
	CredentialMutation
	// Privileged covers administrative and other high-authority changes.
	Privileged
	// StateNeutralRead covers explicitly selected low-risk reads.
	StateNeutralRead
	// DefaultDeny denies unprofiled sensitive/unknown operations before signals.
	DefaultDeny
	// DefaultNeutralRead is the closed audited public-read fallback.
	DefaultNeutralRead
)

// Phase is the owning operation's sole counter-mutation phase. Assessment itself
// does not mutate counters; it cannot replace reserve/finalize ownership.
type Phase string

const (
	BeforeCredential   Phase = "before_credential_or_provider_work"
	ReserveWithCommand Phase = "reserve_with_owning_command"
	BeforeReturn       Phase = "before_return"
)

// Dimension is a closed key-scope component, never a raw storage key.
type Dimension string

const (
	TenantDimension           Dimension = "tenant"
	NetworkDimension          Dimension = "canonical_network"
	DeviceDimension           Dimension = "device"
	IdentifierDimension       Dimension = "canonical_identifier_digest"
	SubjectDimension          Dimension = "subject"
	SessionDimension          Dimension = "session"
	ActorDimension            Dimension = "actor"
	ResourceDimension         Dimension = "target_or_resource"
	SubjectOrNetworkDimension Dimension = "subject_or_network"
)

// UnknownPolicy cannot be selected by an evaluation caller.
type UnknownPolicy uint8

const (
	DenyUnknown UnknownPolicy = iota + 1
	StepUpWithIndependentFactor
)

// VelocityLimits contains explicit deployment bounds. No numeric defaults are
// provided. Maximum supported ceilings are 4 dimensions, 16 counters, one hour,
// 120 attempts and one hour retry-after. KeyBytes must be exactly 64.
type VelocityLimits struct {
	MaxDimensions, MaxCounters int
	MaxWindow                  time.Duration
	MaxLimit                   uint64
	KeyBytes                   int
	RetryAfterMax              time.Duration
}

// Profile is immutable after construction. Dimensions/phase match the closed
// class exactly. RequiredSignals names the complete bounded mandatory set;
// omitted, unavailable and spoofable entries never count as clean. Numeric
// values must be supplied from the selected configuration authority. No profile
// instance, failure policy or dimension list belongs in a caller request.
type Profile struct {
	Class           ProfileClass
	Phase           Phase
	Dimensions      []Dimension
	Window          time.Duration
	Limit           uint64
	ThresholdAction DecisionAction
	EvidenceTTL     time.Duration
	Unknown         UnknownPolicy
	MaxCounters     int
	RequiredSignals []string
}

// PolicyConfig fixes all four profiles and positive policy version. Construction
// copies all slices; concurrent caller mutation during construction is forbidden.
type PolicyConfig struct {
	Version  uint64
	Limits   VelocityLimits
	Profiles []Profile
	HIBP     HIBPPolicy
	// PasskeyDiscovery explicitly permits identifier-free resident signin for
	// the two canonical passkey signin operations only. Missing identifiers
	// remove just that counter; all Authentication limits/signals remain.
	// This is trusted startup policy, never a browser-selected override.
	PasskeyDiscovery bool
}

// Policy is immutable, resource-free and safe for concurrent reads. Zero is
// invalid. It owns no store, clock or provider and never issues evidence.
type Policy struct{ state *policyState }
type policyState struct {
	version          uint64
	limits           VelocityLimits
	profiles         map[ProfileClass]Profile
	hibpTTL          time.Duration
	hibpOperations   map[Action]bool
	passkeyDiscovery bool
}

type profileBounds struct {
	window   time.Duration
	limit    uint64
	evidence time.Duration
	counters int
}

// NewPolicy admits explicit bounded profiles against the pinned complete
// canonical operation catalog. Missing/duplicate classes and contradictory
// phases/dimensions/failure behavior return zero with ErrInvalidPolicy. It does
// not imply durable counter ownership or production configuration readiness.
func NewPolicy(c PolicyConfig) (Policy, error) {
	l := c.Limits
	if c.Version == 0 || len(c.Profiles) != 4 || l.MaxDimensions < 1 || l.MaxDimensions > 4 || l.MaxCounters < 1 || l.MaxCounters > 16 || l.MaxWindow <= 0 || l.MaxWindow > time.Hour || l.MaxLimit == 0 || l.MaxLimit > 120 || l.KeyBytes != 64 || l.RetryAfterMax <= 0 || l.RetryAfterMax > time.Hour {
		return Policy{}, ErrInvalidPolicy
	}
	s := &policyState{version: c.Version, limits: l, profiles: make(map[ProfileClass]Profile, 4), passkeyDiscovery: c.PasskeyDiscovery}
	for _, p := range c.Profiles {
		if _, duplicate := s.profiles[p.Class]; duplicate || !validProfile(p, l) {
			return Policy{}, ErrInvalidPolicy
		}
		p.Dimensions = slices.Clone(p.Dimensions)
		p.RequiredSignals = slices.Clone(p.RequiredSignals)
		s.profiles[p.Class] = p
	}
	if len(c.HIBP.Operations) == 0 {
		if c.HIBP.CacheTTL != 0 {
			return Policy{}, ErrInvalidPolicy
		}
	} else {
		if len(c.HIBP.Operations) > 8 || c.HIBP.CacheTTL < time.Hour || c.HIBP.CacheTTL > 7*24*time.Hour {
			return Policy{}, ErrInvalidPolicy
		}
		s.hibpTTL = c.HIBP.CacheTTL
		s.hibpOperations = make(map[Action]bool, len(c.HIBP.Operations))
		for _, operation := range c.HIBP.Operations {
			class, known := canonicalOperations[operation]
			profile := s.profiles[class]
			if !known || !passwordCreating(operation) || s.hibpOperations[operation] || len(profile.RequiredSignals) >= 32 || slices.Contains(profile.RequiredSignals, "hibp") {
				return Policy{}, ErrInvalidPolicy
			}
			s.hibpOperations[operation] = true
		}
	}
	return Policy{state: s}, nil
}

func validProfile(p Profile, l VelocityLimits) bool {
	bound, known := referenceProfileBounds[p.Class]
	if !known || p.Window > bound.window || p.Limit > bound.limit || p.EvidenceTTL > bound.evidence || p.MaxCounters > bound.counters {
		return false
	}
	var dimensions []Dimension
	phase, threshold, unknown := ReserveWithCommand, Deny, DenyUnknown
	switch p.Class {
	case Authentication:
		dimensions = []Dimension{TenantDimension, NetworkDimension, DeviceDimension, IdentifierDimension}
		phase, threshold = BeforeCredential, Throttle
	case CredentialMutation:
		dimensions = []Dimension{TenantDimension, SubjectDimension, SessionDimension, NetworkDimension}
	case Privileged:
		dimensions = []Dimension{TenantDimension, ActorDimension, ResourceDimension, NetworkDimension}
	case StateNeutralRead:
		dimensions = []Dimension{TenantDimension, SubjectOrNetworkDimension}
		phase, threshold, unknown = BeforeReturn, Throttle, StepUpWithIndependentFactor
	default:
		return false
	}
	if p.Phase != phase || p.ThresholdAction != threshold || p.Unknown != unknown || !slices.Equal(p.Dimensions, dimensions) || len(dimensions) > l.MaxDimensions || p.Window <= 0 || p.Window > l.MaxWindow || p.Limit == 0 || p.Limit > l.MaxLimit || p.EvidenceTTL <= 0 || p.EvidenceTTL > p.Window || p.MaxCounters != len(dimensions) || p.MaxCounters > l.MaxCounters || len(p.RequiredSignals) == 0 || len(p.RequiredSignals) > 32 {
		return false
	}
	seen := make(map[string]bool, len(p.RequiredSignals))
	for _, name := range p.RequiredSignals {
		if !signalName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// Admission freezes operation, version and owned profile projection. A closed
// fallback has no profile, and Preflight is deny/allow; Profile selections have
// empty Preflight and require assessment. This is not audited permission to run.
type Admission struct {
	Operation     Action
	PolicyVersion uint64
	Profile       Profile
	Preflight     DecisionAction
}

// Admit rejects aliases/unlisted operations before provider or state access.
// Returned slices are independently owned and cannot change Policy.
func (p Policy) Admit(action Action) (Admission, error) {
	if p.state == nil {
		return Admission{}, ErrInvalidPolicy
	}
	if len(action) == 0 || len(action) > 128 {
		return Admission{}, ErrInvalidAction
	}
	class, ok := canonicalOperations[action]
	if !ok {
		return Admission{}, ErrInvalidAction
	}
	a := Admission{Operation: action, PolicyVersion: p.state.version}
	if class == DefaultDeny {
		a.Preflight = Deny
		return a, nil
	}
	if class == DefaultNeutralRead {
		a.Preflight = Allow
		return a, nil
	}
	a.Profile = p.state.profiles[class]
	a.Profile.Dimensions = slices.Clone(a.Profile.Dimensions)
	a.Profile.RequiredSignals = slices.Clone(a.Profile.RequiredSignals)
	if p.state.hibpOperations[action] {
		a.Profile.RequiredSignals = append(a.Profile.RequiredSignals, "hibp")
	}
	return a, nil
}

// Context is a trusted server evaluation binding, not HTTP input. Independent-
// factor availability must come from configuration/current server state, never
// a request assertion. Now is one trusted decision-clock sample; it cannot
// refresh signal timestamps or issue an authoritative validity lease.
type Context struct {
	Tenant            string
	Operation         Action
	Attempt           string
	Now               time.Time
	IndependentFactor bool
}

// Format redacts correlated scope and time metadata.
func (Context) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "risk.Context(redacted)") }

// SignalState preserves unavailable, unknown and deliberately skipped facts.
type SignalState uint8

const (
	SignalClean SignalState = iota + 1
	SignalDeny
	SignalThrottle
	SignalStepUp
	SignalUnavailable
	SignalUnknown
	SignalSkipped
	// SignalPositive is a normalized positive risk fact, not a deny decision.
	// Existing state numeric identities are unchanged. This initial fact profile
	// admits only scoped HIBP breach observations; policy owns their consequences.
	SignalPositive
)

// SignalTrust distinguishes configured server sources from spoofable hints.
// A flag alone proves no provenance; only owned orchestration may supply facts.
type SignalTrust uint8

const (
	ServerVerified SignalTrust = iota + 1
	RequestHint
)

// Signal is normalized bounded trusted-source output. Raw provider payloads,
// hashes, network identifiers and credentials never belong here. Selected HIBP
// observations retain bounded BreachCount/Failure, original ObservedAt and
// ProviderValidUntil, plus a separate local CheckedAt and derived ExpiresAt.
// Other sources retain the original short-lived interval contract. Skipped
// entries can only accompany an independently established irreversible deny.
type Signal struct {
	Tenant                        string
	Operation                     Action
	Attempt, Name                 string
	State                         SignalState
	Trust                         SignalTrust
	ObservedAt, ExpiresAt         time.Time
	RetryAfter                    time.Duration
	BreachCount                   uint64
	Failure                       ProviderFailure
	ProviderValidUntil, CheckedAt time.Time
}

// Format redacts all correlation metadata.
func (Signal) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "risk.Signal(redacted)") }

// SignalSummary records normalized outcome only, not a provider payload or key.
type SignalSummary struct {
	Name        string
	State       SignalState
	BreachCount uint64
	Failure     ProviderFailure
}

// Decision is a closed pure assessment output. RetryAfter is present only for
// attributable throttle; unknown state never fabricates retry metadata.
type Decision struct {
	Action     DecisionAction
	RetryAfter time.Duration
}

// Assessment contains bounded internal summaries in mandatory policy order.
// It is neither a public RiskEvidence response nor audit persistence. Copies
// own their summary slices and may be inspected only within trusted workflows.
type Assessment struct {
	Decision      Decision
	PolicyVersion uint64
	Signals       []SignalSummary
}

// Assess deterministically combines all mandatory normalized signals using
// deny > step-up > throttle > allow. Inputs must come from trusted orchestration;
// structural checks establish no source provenance. Missing/spoofable signals
// use the fixed action policy. It performs no provider IO, audit, counter
// mutation, evidence issuance, authorization, override or session revocation.
// Callers must not execute a protected effect from this pure result alone.
// Context cancellation is preserved; nil/invalid input returns no assessment.
func (p Policy) Assess(ctx context.Context, c Context, input []Signal) (Assessment, error) {
	return p.assess(ctx, c, input, false)
}

func (p Policy) assess(ctx context.Context, c Context, input []Signal, protectedProviders bool) (Assessment, error) {
	if ctx == nil {
		return Assessment{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return Assessment{}, err
	}
	a, err := p.Admit(c.Operation)
	if err != nil {
		return Assessment{}, err
	}
	if protectedProviders {
		commandReserved := a.Profile.Class == CredentialMutation && a.Profile.Phase == ReserveWithCommand
		// Phone reset's native evidence owner owns the originally charged
		// Authentication velocity and rechecks its allowance during atomic evidence
		// use. Hash preparation must not charge again or fabricate a clean fact.
		// This exact HIBP-enabled completion is the only authentication exception;
		// the provider-only result still grants no counter or mutation authority.
		phoneResetEvidence := c.Operation == "identity.phone.password-reset-complete" && a.Profile.Class == Authentication && a.Profile.Phase == BeforeCredential && p.state.hibpOperations[c.Operation]
		if a.Preflight != "" || (!commandReserved && !phoneResetEvidence) || !slices.Contains(a.Profile.RequiredSignals, "velocity") {
			return Assessment{}, ErrInvalidAction
		}
		// Admit returns owned slices. Remove only the signal whose actual
		// allowance belongs to mandatory native reservation/current-use checks.
		a.Profile.RequiredSignals = slices.DeleteFunc(a.Profile.RequiredSignals, func(name string) bool { return name == "velocity" })
	}
	if !scopeID(c.Tenant) || !scopeID(c.Attempt) || !validTime(c.Now) {
		return Assessment{}, ErrInvalidContext
	}
	result := Assessment{Decision: Decision{Action: Allow}, PolicyVersion: a.PolicyVersion}
	// Closed defaults never inspect even malformed caller signals.
	if a.Preflight != "" {
		result.Decision.Action = a.Preflight
		return result, nil
	}
	if len(input) > len(a.Profile.RequiredSignals) {
		return Assessment{}, ErrInvalidSignal
	}
	provided := make(map[string]Signal, len(input))
	explicitDeny := false
	for _, s := range input {
		if !signalName(s.Name) {
			return Assessment{}, ErrInvalidSignal
		}
		ttl := time.Duration(0)
		if p.state.hibpOperations[c.Operation] {
			ttl = p.state.hibpTTL
		}
		if _, duplicate := provided[s.Name]; duplicate || !slices.Contains(a.Profile.RequiredSignals, s.Name) || !validSignal(s, c, a.Profile, p.state.limits, ttl) {
			return Assessment{}, ErrInvalidSignal
		}
		provided[s.Name] = s
		if irreversibleDeny(s) {
			explicitDeny = true
		}
	}
	for _, name := range a.Profile.RequiredSignals {
		if err := ctx.Err(); err != nil {
			return Assessment{}, err
		}
		s, exists := provided[name]
		state := s.State
		if !exists || s.Trust != ServerVerified {
			state = SignalUnavailable
		}
		if state == SignalSkipped && !explicitDeny {
			return Assessment{}, ErrInvalidSignal
		}
		summary := SignalSummary{Name: name, State: state}
		if exists && s.Trust == ServerVerified {
			summary.BreachCount = s.BreachCount
			summary.Failure = s.Failure
		}
		result.Signals = append(result.Signals, summary)
		decision := Allow
		switch state {
		case SignalDeny, SignalPositive:
			decision = Deny
		case SignalThrottle:
			decision = Throttle
		case SignalStepUp:
			decision = StepUp
		case SignalUnavailable, SignalUnknown:
			decision = Deny
			if a.Profile.Unknown == StepUpWithIndependentFactor && c.IndependentFactor {
				decision = StepUp
			}
		}
		if rank(decision) > rank(result.Decision.Action) {
			result.Decision = Decision{Action: decision}
		}
		if decision == Throttle && result.Decision.Action == Throttle && s.RetryAfter > result.Decision.RetryAfter {
			result.Decision.RetryAfter = s.RetryAfter
		}
	}
	return result, nil
}

func validSignal(s Signal, c Context, p Profile, l VelocityLimits, hibpTTL time.Duration) bool {
	if s.Tenant != c.Tenant || s.Operation != c.Operation || s.Attempt != c.Attempt || s.State < SignalClean || s.State > SignalPositive || s.Trust < ServerVerified || s.Trust > RequestHint || s.RetryAfter < 0 || s.RetryAfter > l.RetryAfterMax || s.RetryAfter > p.Window || (s.State != SignalThrottle && s.RetryAfter != 0) || (s.State == SignalThrottle && s.RetryAfter == 0) {
		return false
	}
	if s.Name == "hibp" && hibpTTL != 0 {
		return validPasswordSignal(s, c, p, hibpTTL)
	}
	if s.State == SignalPositive || s.BreachCount != 0 || s.Failure != 0 || !s.ProviderValidUntil.IsZero() || !s.CheckedAt.IsZero() {
		return false
	}
	if (s.State == SignalUnknown || s.State == SignalUnavailable || s.State == SignalSkipped) && s.ObservedAt.IsZero() && s.ExpiresAt.IsZero() {
		return true
	}
	return validTime(s.ObservedAt) && validTime(s.ExpiresAt) && !s.ObservedAt.After(c.Now) && s.ExpiresAt.After(c.Now) && s.ExpiresAt.After(s.ObservedAt) && s.ExpiresAt.Sub(s.ObservedAt) <= p.EvidenceTTL
}

func rank(action DecisionAction) int {
	switch action {
	case Deny:
		return 4
	case StepUp:
		return 3
	case Throttle:
		return 2
	case Allow:
		return 1
	}
	return 0
}
func validTime(t time.Time) bool { return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999 }
func signalName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 'a' || b > 'z' {
			if b < '0' || b > '9' {
				if b != '-' && b != '_' {
					return false
				}
			}
		}
	}
	return true
}
func scopeID(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
