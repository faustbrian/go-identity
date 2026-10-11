package risk

import "context"

// ProtectedProviderAssessment is a provider-only preparation result, not a
// complete Assessment, counter allowance or mutation authority. Allow means
// mandatory provider observations passed; command-owned velocity has NOT been
// assessed. The protected owner must reserve and recheck its exact matching
// counter policy atomically with the mutation. Signals excludes velocity and
// owns its summary slice. No provider, store or audit IO is performed.
type ProtectedProviderAssessment struct {
	Decision      Decision
	PolicyVersion uint64
	Signals       []SignalSummary
}

// AssessProtectedProviders checks immutable provider facts before hashing and
// during protected credential-mutation rechecks. Only the closed
// CredentialMutation/ReserveWithCommand profile with mandatory velocity is
// supported; other profiles return ErrInvalidAction. The sole deferred signal
// is velocity, whose allowance must come from native protected counters.
// Caller-supplied velocity is rejected, never trusted or synthesized. All other
// required signals, including selected HIBP, retain ordinary scope, freshness,
// precedence and fail-closed policy. Cancellation and malformed input preserve
// Assess error semantics. Concurrent calls are safe; inputs are not modified.
func (p Policy) AssessProtectedProviders(ctx context.Context, c Context, input []Signal) (ProtectedProviderAssessment, error) {
	a, err := p.assess(ctx, c, input, true)
	if err != nil {
		return ProtectedProviderAssessment{}, err
	}
	return ProtectedProviderAssessment{Decision: a.Decision, PolicyVersion: a.PolicyVersion, Signals: a.Signals}, nil
}
