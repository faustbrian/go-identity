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
	Name      string
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
}

// NewEvaluator rejects missing, duplicate or extraneous mandatory-source owners,
// invalid callbacks and unbounded timeouts with ErrInvalidPolicy. Construction
// invokes no callback and copies the source slice into owned immutable state.
func NewEvaluator(c EvaluatorConfig) (Evaluator, error) {
	if c.Policy.state == nil || c.Clock == nil || c.Timeout <= 0 || c.Timeout > time.Minute || len(c.Sources) == 0 || len(c.Sources) > 128 {
		return Evaluator{}, ErrInvalidPolicy
	}
	required := make(map[string]bool)
	for _, profile := range c.Policy.state.profiles {
		for _, name := range profile.RequiredSignals {
			required[name] = true
		}
	}
	if len(required) != len(c.Sources) {
		return Evaluator{}, ErrInvalidPolicy
	}
	s := &evaluatorState{policy: c.Policy, clock: c.Clock, timeout: c.Timeout, sources: make(map[string]Source, len(c.Sources)), independentFactor: c.IndependentFactor}
	for _, source := range c.Sources {
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
// This method does not audit, mutate counters, issue evidence or grant permission
// to execute. Issuing phases fail before clock, factor or source access.
func (e Evaluator) Evaluate(ctx context.Context, request EvaluateRequest) (EvaluateResult, error) {
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
		if readErr != nil || childErr != nil || !now.Before(sourceStart.Add(source.Timeout)) {
			signal = Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: SignalUnavailable, Trust: ServerVerified}
		}
		if signal.Name != name || !validSignal(signal, c, a.Profile, e.state.policy.state.limits) {
			return evaluationFailure(ErrInvalidSignal)
		}
		if signal.State == SignalSkipped {
			return evaluationFailure(ErrInvalidSignal)
		}
		if signal.State == SignalDeny && signal.Trust == ServerVerified {
			denied = true
		}
		signals = append(signals, signal)
	}
	if err := bounded.Err(); err != nil {
		return evaluationFailure(err)
	}
	now := e.state.clock()
	if err := evaluationTime(now, last, start, e.state.timeout); err != nil {
		return evaluationFailure(err)
	}
	c.Now = now
	assessment, err := e.state.policy.Assess(bounded, c, signals)
	if err != nil {
		return evaluationFailure(err)
	}
	return safeEvaluation(assessment), nil
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
