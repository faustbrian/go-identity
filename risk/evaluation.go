package risk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrUnsupportedIssuance means this development evaluator cannot issue durable
// evidence. It never substitutes a pure decision for an issuing phase.
var ErrUnsupportedIssuance = errors.New("risk: unsupported issuance")

// IssuancePhase has exactly three protocol values. Zero is invalid. Only
// NonIssuing is executable until durable command contributors are implemented.
type IssuancePhase string

const (
	NonIssuing           IssuancePhase = "none"
	PhoneResetInitiation IssuancePhase = "phone-reset-initiation"
	PhoneResetCompletion IssuancePhase = "phone-reset-completion"
)

// Source is a server-configured mandatory normalized-fact reader. Read receives
// a bounded child context and trusted evaluation binding; it must obey context
// cancellation, own resource cleanup and be safe for concurrent invocations.
// It may resolve facts from owned state using the attempt binding, but must not
// mutate counters, issue evidence or perform a protected operation. Persistence
// and providers must use the named platform adapters, not application stores.
// Source output must preserve original observation and expiry, exact scope,
// name and trust. Errors are normalized to unavailable without disclosure or
// automatic retry. Expensive permits skipping only after a verified deny.
type Source struct {
	Name string
	// Version is a pinned source/configuration identity, required by evidence
	// issuance. Empty remains compatible for non-issuing assessment only.
	Version   string
	Timeout   time.Duration
	Expensive bool
	Read      func(context.Context, Context) (Signal, error)
}

// EvaluatorConfig pins immutable policy and the exact union of its mandatory
// sources. No source or fail behavior can be selected per request. Clock must
// return trusted UTC instants and support concurrent reads. Timeout is explicit,
// positive and at most one minute; each source timeout must fit inside it.
// IndependentFactor, when configured, resolves current server factor availability
// with the same bounded context; request flags cannot supply that authority.
// Callbacks must not be changed or concurrently mutated after construction.
type EvaluatorConfig struct {
	Policy            Policy
	Clock             func() time.Time
	Timeout           time.Duration
	Sources           []Source
	IndependentFactor func(context.Context, Context) (bool, error)
	// Counters optionally installs the sole velocity owner. Every policy profile
	// must require velocity, Sources must omit it, and this coordinator must use
	// the exact same immutable Policy. The value is copied, not the pointer.
	// Nil retains source-only assessment, not complete abuse enforcement.
	Counters *CounterCoordinator
}

// Evaluator owns bounded server-source orchestration. It starts no goroutine,
// holds no locks across callbacks, and is safe for concurrent use when configured
// callbacks are. It has no shutdown or durable mutation authority. Its output
// is not complete risk-service permission, journal evidence or authentication.
type Evaluator struct{ state *evaluatorState }
type evaluatorState struct {
	policy            Policy
	clock             func() time.Time
	timeout           time.Duration
	sources           map[string]Source
	independentFactor func(context.Context, Context) (bool, error)
	counters          CounterCoordinator
}

// NewEvaluator rejects missing, duplicate or extraneous mandatory-source owners,
// invalid callbacks and unbounded timeouts with ErrInvalidPolicy. Construction
// invokes no callback and copies the source slice into owned immutable state.
func NewEvaluator(c EvaluatorConfig) (Evaluator, error) {
	if c.Policy.state == nil || c.Clock == nil || c.Timeout <= 0 || c.Timeout > time.Minute || (len(c.Sources) == 0 && c.Counters == nil) || len(c.Sources) > 128 {
		return Evaluator{}, ErrInvalidPolicy
	}
	required := make(map[string]bool)
	for _, profile := range c.Policy.state.profiles {
		velocity := false
		for _, name := range profile.RequiredSignals {
			required[name] = true
			velocity = velocity || name == "velocity"
		}
		if c.Counters != nil && !velocity {
			return Evaluator{}, ErrInvalidPolicy
		}
	}
	if len(c.Policy.state.hibpOperations) > 0 {
		required["hibp"] = true
	}
	if c.Counters != nil {
		if c.Counters.state == nil || c.Counters.state.policy.state != c.Policy.state {
			return Evaluator{}, ErrInvalidPolicy
		}
		delete(required, "velocity")
	}
	if len(required) != len(c.Sources) {
		return Evaluator{}, ErrInvalidPolicy
	}
	s := &evaluatorState{policy: c.Policy, clock: c.Clock, timeout: c.Timeout, sources: make(map[string]Source, len(c.Sources)), independentFactor: c.IndependentFactor}
	if c.Counters != nil {
		s.counters = *c.Counters
	}
	for _, source := range c.Sources {
		if source.Version != "" && (!scopeID(source.Version) || len(source.Version) > 64) {
			return Evaluator{}, ErrInvalidPolicy
		}
		if !signalName(source.Name) || !required[source.Name] || source.Read == nil || source.Timeout <= 0 || source.Timeout > c.Timeout {
			return Evaluator{}, ErrInvalidPolicy
		}
		if _, duplicate := s.sources[source.Name]; duplicate {
			return Evaluator{}, ErrInvalidPolicy
		}
		s.sources[source.Name] = source
	}
	return Evaluator{state: s}, nil
}

// EvaluateRequest is server workflow input, never direct HTTP input. Context's
// Now and IndependentFactor fields are ignored: the configured clock and factor
// resolver own them. Tenant, operation and attempt must already be server-bound.
// There is intentionally no caller purpose, policy, decision or evidence field.
type EvaluateRequest struct {
	Context Context
	Phase   IssuancePhase
	// Subject contains exact trusted profile dimensions only when Counters is
	// configured. It must be empty for source-only evaluation and closed defaults.
	Subject Subject
}

// Format omits all correlated request metadata.
func (EvaluateRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvaluateRequest(redacted)")
}

// EvaluateResult exposes only a non-issuing decision and policy version. It
// never exposes raw facts, provider errors or one-use evidence. Zero is invalid.
type EvaluateResult struct {
	Decision      Decision
	PolicyVersion uint64
	assessment    Assessment
	counter       *CounterEvaluation
	provenance    *evaluationProvenance
}

// Only a successful owned evaluation can populate issuing provenance. Public
// decision fields and caller-created Assessment values cannot recreate it.
type evaluationProvenance struct {
	owner   *evaluatorState
	context Context
	signals []Signal
}

// Format omits private correlated source and counter state.
func (EvaluateResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvaluateResult(redacted)")
}

// EvaluateError classifies evaluation rejection using a stable redacted cause.
// errors.Is preserves policy/action/context/signal errors and parent cancellation
// or deadline expiry. Source errors are never retained, wrapped or formatted.
type EvaluateError struct{ cause error }

func (e *EvaluateError) Error() string { return "risk: evaluation rejected" }
func (e *EvaluateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
func (*EvaluateError) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvaluateError(redacted)")
}

func evaluationFailure(err error) (EvaluateResult, error) {
	return EvaluateResult{}, &EvaluateError{cause: err}
}

// Evaluate admits the exact canonical operation before source work and runs all
// mandatory readers in policy order. An irreversible verified deny may skip an
// explicitly expensive reader; a skip remains in the retained assessment.
// Positive facts are checked again at the final clock sample, so a later reader
// cannot renew an earlier fact's original interval. Backward clocks, late whole
// evaluations, malformed/foreign facts and parent cancellation return zero.
// A source's error or timeout becomes unavailable under the fixed action policy,
// even if it also returns positive facts; it is not retried. A non-cooperative
// callback cannot be forcibly interrupted, but its late result cannot allow.
// With Counters configured, velocity is mutated exactly once at the selected
// nontransactional profile phase, before provider work or before return. A
// protected-command phase fails before store/provider work; only its future
// shared-Work participant may mutate it. Later failure never rolls back an
// attempt: the known outcome remains private for the owning risk service.
// This method does not audit, issue evidence or grant permission to execute.
// Issuing phases fail before clock, factor, counter or source access.
func (e Evaluator) Evaluate(ctx context.Context, request EvaluateRequest) (result EvaluateResult, err error) {
	var counted *CounterEvaluation
	defer func() { result.counter = counted }()
	if e.state == nil {
		return evaluationFailure(ErrInvalidPolicy)
	}
	if ctx == nil {
		return evaluationFailure(ErrInvalidContext)
	}
	if err := ctx.Err(); err != nil {
		return evaluationFailure(err)
	}
	if request.Phase != NonIssuing {
		return evaluationFailure(ErrUnsupportedIssuance)
	}
	c := request.Context
	a, err := e.state.policy.Admit(c.Operation)
	if err != nil {
		return evaluationFailure(err)
	}
	if !scopeID(c.Tenant) || !scopeID(c.Attempt) {
		return evaluationFailure(ErrInvalidContext)
	}
	if request.Subject != (Subject{}) && (e.state.counters.state == nil || a.Preflight != "") {
		return evaluationFailure(ErrInvalidCounterCommand)
	}
	bounded, cancel := context.WithTimeout(ctx, e.state.timeout)
	defer cancel()
	start := e.state.clock()
	if !validTime(start) {
		return evaluationFailure(ErrInvalidContext)
	}
	c.Now, c.IndependentFactor = start, false
	last := start
	if a.Preflight != "" {
		assessment, err := e.state.policy.Assess(bounded, c, nil)
		if err != nil {
			return evaluationFailure(err)
		}
		return safeEvaluation(assessment), nil
	}
	var command CounterCommand
	if e.state.counters.state != nil {
		command, err = e.state.counters.Prepare(c, request.Subject, a.Profile.Phase)
		if err != nil {
			return evaluationFailure(err)
		}
	}
	mutate := func() error {
		value, err := e.state.counters.Mutate(bounded, command)
		counted = &value
		if err != nil {
			return err
		}
		now := e.state.clock()
		if err := evaluationTime(now, last, start, e.state.timeout); err != nil {
			return err
		}
		last, c.Now = now, now
		return nil
	}
	if command.state != nil && a.Profile.Phase == BeforeCredential {
		if err := mutate(); err != nil {
			return evaluationFailure(err)
		}
	}
	if a.Profile.Unknown == StepUpWithIndependentFactor && e.state.independentFactor != nil {
		factor, readErr := e.state.independentFactor(bounded, c)
		if err := bounded.Err(); err != nil {
			return evaluationFailure(err)
		}
		now := e.state.clock()
		if err := evaluationTime(now, last, start, e.state.timeout); err != nil {
			return evaluationFailure(err)
		}
		last, c.Now = now, now
		// Resolver failures cannot assert independent-factor availability.
		c.IndependentFactor = readErr == nil && factor
	}
	signals := make([]Signal, 0, len(a.Profile.RequiredSignals))
	denied := false
	for _, name := range a.Profile.RequiredSignals {
		if err := bounded.Err(); err != nil {
			return evaluationFailure(err)
		}
		if name == "velocity" && command.state != nil {
			if counted == nil {
				// BeforeReturn executes after all provider work. Keep the exact
				// mandatory slot; replace it only with the owned post-state.
				signals = append(signals, Signal{})
			} else {
				signals = append(signals, counted.Signal)
			}
			continue
		}
		source := e.state.sources[name]
		if denied && source.Expensive {
			signals = append(signals, Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: SignalSkipped, Trust: ServerVerified})
			continue
		}
		sourceStart := last
		child, stop := context.WithTimeout(bounded, source.Timeout)
		signal, readErr := source.Read(child, c)
		childErr := child.Err()
		stop()
		if err := bounded.Err(); err != nil {
			return evaluationFailure(err)
		}
		now := e.state.clock()
		if err := evaluationTime(now, last, start, e.state.timeout); err != nil {
			return evaluationFailure(err)
		}
		last, c.Now = now, now
		ttl := time.Duration(0)
		if e.state.policy.state.hibpOperations[c.Operation] {
			ttl = e.state.policy.state.hibpTTL
		}
		if readErr != nil || childErr != nil || !now.Before(sourceStart.Add(source.Timeout)) {
			// Preserve only validated safe source classification; never retain a
			// positive fact supplied alongside an error or a late result.
			failure := ProviderFailure(0)
			if name == "hibp" && ttl != 0 {
				failure = ProviderUnavailable
				if readErr != nil && childErr == nil && now.Before(sourceStart.Add(source.Timeout)) && signal.Name == name && signal.State == SignalUnavailable && signal.Trust == ServerVerified && validSignal(signal, c, a.Profile, e.state.policy.state.limits, ttl) {
					failure = signal.Failure
				}
			}
			signal = Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: SignalUnavailable, Trust: ServerVerified, Failure: failure}
		}
		if signal.Name != name || !validSignal(signal, c, a.Profile, e.state.policy.state.limits, ttl) {
			return evaluationFailure(ErrInvalidSignal)
		}
		if signal.State == SignalSkipped {
			return evaluationFailure(ErrInvalidSignal)
		}
		if irreversibleDeny(signal) {
			denied = true
		}
		signals = append(signals, signal)
	}
	if command.state != nil && a.Profile.Phase == BeforeReturn {
		if err := mutate(); err != nil {
			return evaluationFailure(err)
		}
		for i, name := range a.Profile.RequiredSignals {
			if name == "velocity" {
				signals[i] = counted.Signal
			}
		}
	}
	if err := bounded.Err(); err != nil {
		return evaluationFailure(err)
	}
	now := e.state.clock()
	if err := evaluationTime(now, last, start, e.state.timeout); err != nil {
		return evaluationFailure(err)
	}
	c.Now = now
	if counted != nil && counted.Signal.State == SignalThrottle {
		for i, name := range a.Profile.RequiredSignals {
			if name == "velocity" {
				signals[i].RetryAfter = counterRetryAfter(counted.result.state.snapshot, a.Profile.Limit, now, e.state.policy.state.limits.RetryAfterMax)
			}
		}
	}
	assessment, err := e.state.policy.Assess(bounded, c, signals)
	if err != nil {
		return evaluationFailure(err)
	}
	result = safeEvaluation(assessment)
	result.provenance = &evaluationProvenance{owner: e.state, context: c, signals: signals}
	return result, nil
}

func safeEvaluation(a Assessment) EvaluateResult {
	return EvaluateResult{Decision: a.Decision, PolicyVersion: a.PolicyVersion, assessment: a}
}

func evaluationTime(now, last, start time.Time, timeout time.Duration) error {
	if !validTime(now) || now.Before(last) {
		return ErrInvalidContext
	}
	if !now.Before(start.Add(timeout)) {
		return context.DeadlineExceeded
	}
	return nil
}
