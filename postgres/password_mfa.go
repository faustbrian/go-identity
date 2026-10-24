package postgres

import identity "github.com/faustbrian/go-identity"

// PasswordMFAChallengeContributor is the closed native challenge-only password
// owner. Validation must match original password/browser custody, the signed
// comparison record, selected user, policy/factor authority and unchanged child
// scope; it is pure and bounded. ApplyFeature rechecks current credential,
// account, policy and factor authority, commits any exact hash upgrade and
// original password evidence, advances pre-auth and persists the continuation
// and its child without creating a session. CheckFeatureCommit repeats original
// expiry and live authority fences. All effects share the sole Work. The child
// cannot outlive original password/pre-auth evidence. No synthetic primary
// capability or session/proof obtained from projected metadata is permitted.
// Implementing this interface grants no authentication or transaction authority.
type PasswordMFAChallengeContributor interface {
	FeatureCommitContributor
	ValidatePasswordMFAChallenge(identity.Command, MFAContinuationPlan) error
}

func validateMFAContinuation(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	if passkeyMFAOperation(p) {
		return validatePasskeyMFAChallenge(owner, command, p)
	}
	if emailVerificationMFAOperation(p) {
		return validateEmailVerificationMFAChallenge(owner, command, p)
	}
	if !passwordMFAOperation(p) {
		return validateMagicLinkConsumption(owner, command, p)
	}
	native, ok := owner.(PasswordMFAChallengeContributor)
	f, feature := command.PasswordSigninFeature()
	secret, _, custody := command.PasswordSigninCustody()
	if !ok || !feature || !custody || secret.Len() == 0 || p.MFAContinuation == nil || p.Capability != nil || f.Operation != p.Feature.Operation {
		return invalidPlan()
	}
	return native.ValidatePasswordMFAChallenge(command, *p.MFAContinuation)
}

// PasswordMFAChallenge lends the original complete challenge scope only during
// its exact registered native owner's protected Apply invocation. Foreign,
// retained, preparation, commit-check and closed handles deny. Password primary
// evidence is not a consumed capability, and no capability use is invented here.
// The owned copy grants no factor/session authority or delivery permission.
func (w Work) PasswordMFAChallenge(owner PasswordMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return MFAContinuationPlan{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.issuance == nil || !validPasswordMFAPlanMode(b, p.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *p.mfaContinuation, nil
}

// PasswordMFAChallenge returns unchanged historical scope to the exact native
// recovery participant. It permits neither comparison, mutation nor credential
// delivery; original committed evidence and journal ownership remain required.
func (w RecoveryWork) PasswordMFAChallenge(owner PasswordMFAChallengeContributor) (MFAContinuationPlan, error) {
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || w.state.plan.issuance == nil || !validPasswordMFAPlanMode(b, w.state.plan.snapshot(), false) {
		return MFAContinuationPlan{}, invalidWork()
	}
	return *cloneMFAContinuationPlan(w.state.plan.mfaContinuation), nil
}
