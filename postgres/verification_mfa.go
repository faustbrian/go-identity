package postgres

import identity "github.com/faustbrian/go-identity"

// EmailVerificationMFAChallengeContributor owns the challenge-only continuation
// after a separately committed registration verification. Validation is pure and
// bounded and must bind that committed parent, original signup browser, selected
// recipient, primary expiry, remember choice and unchanged current factor scope.
// ApplyFeature and CheckFeatureCommit independently fence the native parent's
// primary evidence and current account, identifier, risk and factor authority.
// Only the child challenge, continuation, audit and lifecycle share this Work;
// no parent consumption, password comparison or authenticated session is invented.
// Implementing this interface conveys no authentication or transaction authority.
type EmailVerificationMFAChallengeContributor interface {
	FeatureCommitContributor
	ValidateEmailVerificationMFAChallenge(identity.Command, MFAContinuationPlan) error
}

func validateEmailVerificationMFAChallenge(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	native, ok := owner.(EmailVerificationMFAChallengeContributor)
	f, feature := command.Feature()
	_, browser := command.PreAuthCookie()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	if !ok || !feature || !browser || otp || recovery || p.Feature == nil || f.Operation != p.Feature.Operation || !validEmailVerificationMFAPlanMode(f.Binding, p, true) {
		return invalidPlan()
	}
	return native.ValidateEmailVerificationMFAChallenge(command, *p.MFAContinuation)
}

// EmailVerificationMFAChallenge lends the frozen child declaration only during
// its exact registered native owner's protected Apply. Foreign, retained,
// preparation, commit-check, closed and generation-mismatched handles deny.
// The owned copy is correlation, not proof of its committed parent, browser,
// factor or permission to issue a session. No IO, callbacks or renewal occurs.
func (w Work) EmailVerificationMFAChallenge(owner EmailVerificationMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return MFAContinuationPlan{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.issuance == nil || !validEmailVerificationMFAPlanMode(b, p.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *p.mfaContinuation, nil
}

// EmailVerificationMFAChallenge returns unchanged committed-parent challenge
// scope to its exact native recovery participant. It grants neither mutation,
// primary/factor authentication nor replacement credential disclosure. Returned
// copies cannot change the frozen plan or extend its original expiry.
func (w RecoveryWork) EmailVerificationMFAChallenge(owner EmailVerificationMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || w.state.plan.issuance == nil || !validEmailVerificationMFAPlanMode(b, w.state.plan.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *cloneMFAContinuationPlan(w.state.plan.mfaContinuation), nil
}
