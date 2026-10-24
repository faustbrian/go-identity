package postgres

import identity "github.com/faustbrian/go-identity"

// PasskeyMFAChallengeContributor is the native challenge-only UV assertion
// owner. Pure bounded validation must bind the real verifier-issued transition,
// original browser, selected subject, primary expiry and exact child scope.
// ApplyFeature consumes the genuine ceremony and persists original primary
// provenance, continuation and child atomically in the sole Work, without a
// session. Current account/credential/passkey/policy/factor/risk and original
// expiry must be fenced both in Apply and CheckFeatureCommit. Implementing this
// interface does not itself authenticate a passkey, factor or browser.
type PasskeyMFAChallengeContributor interface {
	FeatureCommitContributor
	ValidatePasskeyMFAChallenge(identity.Command, MFAContinuationPlan) error
}

func validatePasskeyMFAChallenge(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	native, ok := owner.(PasskeyMFAChallengeContributor)
	f, feature := command.Feature()
	_, browser := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, token := command.SessionToken()
	if !ok || !feature || !browser || code || recovery || token || p.Feature == nil || f.Operation != p.Feature.Operation || !validPasskeyMFAPlanMode(f.Binding, p, true) {
		return invalidPlan()
	}
	return native.ValidatePasskeyMFAChallenge(command, *p.MFAContinuation)
}

// PasskeyMFAChallenge lends the frozen declaration only during its exact
// registered native owner's protected Apply. Returned copies grant no proof,
// issuance permission or renewed expiry; retained, foreign and closed Work,
// preparation, recovery and commit-check invocation handles deny.
func (w Work) PasskeyMFAChallenge(owner PasskeyMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return MFAContinuationPlan{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.issuance == nil || !validPasskeyMFAPlanMode(b, p.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *p.mfaContinuation, nil
}

// PasskeyMFAChallenge returns the unchanged historical declaration only to its
// original registered recovery owner. It is not evidence of commitment: recovery
// also inspects expired pending journals. It never repeats assertion/factor
// verification, creates another child or discloses credentials.
func (w RecoveryWork) PasskeyMFAChallenge(owner PasskeyMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || w.state.plan.issuance == nil || !validPasskeyMFAPlanMode(b, w.state.plan.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *cloneMFAContinuationPlan(w.state.plan.mfaContinuation), nil
}
