package postgres

import "fmt"

// CaptchaReplayOwnership is the original authoritative fingerprint and current
// generation, exposed only during an exact declared native invocation. It is
// linkage, not current authorization, replay ownership or commitment proof.
// Adapters must compare both against their locked primary winner before use.
type CaptchaReplayOwnership struct {
	Fingerprint [32]byte
	Generation  uint64
	// PreviousGeneration is nonzero only during primary recovery. It names
	// the retained participant owner being reconciled, not mutation authority.
	PreviousGeneration uint64
}

// Format redacts native command linkage.
func (CaptchaReplayOwnership) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaReplayOwnership(redacted)"))
}

// MarshalJSON rejects native custody serialization.
func (CaptchaReplayOwnership) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects native custody serialization.
func (CaptchaReplayOwnership) MarshalText() ([]byte, error) { return nil, invalidWork() }

// CaptchaReplayOwnership exposes current-generation linkage only to the exact
// active native feature owner with an admitted CAPTCHA replay declaration.
// Returned/foreign/zero/expired Work denies without IO or callbacks. Copies
// cannot renew ownership, and this supplies no predecessor-transfer authority.
func (w Work) CaptchaReplayOwnership(p CaptchaReplayContributor) (CaptchaReplayOwnership, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil || w.state.execution == nil || w.state.execution.reservation == nil {
		return CaptchaReplayOwnership{}, invalidWork()
	}
	r := w.state.execution.reservation
	if r.plan == nil || !r.plan.captchaReplay || r.plan.fingerprint == ([32]byte{}) || w.state.generation == 0 || r.journal.generation != w.state.generation || r.plan.binding != w.state.binding || r.plan.registry != w.state.registry {
		return CaptchaReplayOwnership{}, invalidWork()
	}
	return CaptchaReplayOwnership{Fingerprint: r.plan.fingerprint, Generation: w.state.generation}, nil
}

// CaptchaReplayOwnership exposes frozen linkage during the exact native
// recovery-only invocation. It grants no SQL mutation, release or new issuance
// authority. Current disclosure authorization remains the coordinator's job.
func (w RecoveryWork) CaptchaReplayOwnership(p CaptchaReplayContributor) (CaptchaReplayOwnership, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil || !w.state.plan.captchaReplay || w.state.plan.fingerprint == ([32]byte{}) || w.state.work.state.execution == nil || w.state.work.state.execution.reservation == nil {
		return CaptchaReplayOwnership{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	previous := r.journal.previousGeneration
	if previous == 0 || previous == ^uint64(0) || r.journal.generation != previous+1 || w.state.work.state.generation != r.journal.generation || r.plan != w.state.plan || r.plan.binding != w.state.work.state.binding || r.plan.registry != w.state.work.state.registry {
		return CaptchaReplayOwnership{}, invalidWork()
	}
	return CaptchaReplayOwnership{Fingerprint: w.state.plan.fingerprint, Generation: r.journal.generation, PreviousGeneration: previous}, nil
}
