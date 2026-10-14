package postgres

import identity "github.com/faustbrian/go-identity"

// MFALoginSendCounterContributor lends the authenticated original subject only
// to native counter execution. The registered MFA owner must bind it to the
// complete immutable command, signed child, confirmed factor and original
// consumed-primary browser. Its input-admission and commit checks separately
// fence current authority before charging/generation and after bounded waits.
// This pure method must not perform IO, sample a clock, mutate state or grant
// proof/consumption authority. Configuration and original inputs are immutable;
// independent calls may overlap. It does not introduce a session or journal.
type MFALoginSendCounterContributor interface {
	FeatureInputAdmissionContributor
	MFALoginSendCounterSubject(identity.Command) (identity.UserID, error)
}

// MFALoginSendScope lends the registered MFA owner's original resolved account
// and immutable browser-flow ID only to this exact native counter invocation.
// The command journal remains anonymous. Closed, returned, foreign and other
// profiles deny; no factor comparison, child use, SQL or freshness renewal occurs.
// These scalars grant no independent authorization or transaction authority.
func (w CommandCounterWork) MFALoginSendScope(owner CommandCounterContributor) (user identity.UserID, browser string, err error) {
	defer func() {
		if recover() != nil {
			user, browser, err = "", "", invalidWork()
		}
	}()
	if _, err := w.Binding(owner); err != nil {
		return "", "", err
	}
	p := w.state.work.state.execution.reservation.plan
	c := w.state.work.state.execution.coordinator
	s, ok := w.state.command.Feature()
	operation := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	descriptor := ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
	_, cookie := w.state.command.PreAuthCookie()
	_, code := w.state.command.OneTimeCode()
	_, recovery := w.state.command.RecoveryCode()
	if !ok || !cookie || code || recovery || p.registry != c.registry.state || p.feature == nil || p.feature.Operation != operation || p.feature.Contributor != descriptor || s.Operation != operation || s.Binding != p.binding || w.state.work.state.binding != p.binding || s.Binding.UserID != "" || s.Binding.AnonymousFlowID == "" || p.capability != nil || p.mfaCompletion != nil || p.mfaContinuation != nil {
		return "", "", invalidWork()
	}
	if _, err := identity.ParseCommandID(s.Binding.RecordID); err != nil {
		return "", "", invalidWork()
	}
	entry, err := c.registry.selectFeatureOperation(*p.feature)
	if err != nil {
		return "", "", invalidWork()
	}
	native, ok := entry.contributor.(MFALoginSendCounterContributor)
	if !ok || nilContributor(native) {
		return "", "", invalidWork()
	}
	user, err = native.MFALoginSendCounterSubject(w.state.command)
	if err != nil || user == "" || len(user) > 256 {
		return "", "", invalidWork()
	}
	return user, s.Binding.AnonymousFlowID, nil
}

// MFALoginSendScope retains the same registered-source guard during current
// allowance checks. It neither charges again nor converts metadata to a proof.
func (w CommandCounterAdmissionWork) MFALoginSendScope(owner CommandCounterContributor) (identity.UserID, string, error) {
	return (CommandCounterWork{state: w.state}).MFALoginSendScope(owner)
}
