package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Owner helpers can reject a cursor/budget precondition before executing SQL.
// Remember every live admission failure even if that low-level rejection did
// not itself poison Work; later cursor cleanup must not erase a denied check.
func otpAuthorityFailure(ctx context.Context, w Work, err error) error {
	if err != nil {
		return w.fail(ctx, err)
	}
	return nil
}

// Only live, phase-validated handles reach this helper. A retained handle must
// never poison a later invocation that happens to share its original Work.
func otpAuthorityScope(ctx context.Context, w Work, b identity.CommandBinding, bindingErr error) (Work, identity.CommandBinding, error) {
	if ctx == nil {
		return Work{}, identity.CommandBinding{}, w.fail(w.state.ctx, invalidWork())
	}
	if bindingErr != nil {
		return Work{}, identity.CommandBinding{}, w.fail(ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return Work{}, identity.CommandBinding{}, w.fail(ctx, err)
	}
	return w, b, nil
}

func (h OTPAttemptWork) authorityScope(ctx context.Context, p OTPAttemptContributor) (Work, identity.CommandBinding, error) {
	if err := h.usable(); err != nil {
		return Work{}, identity.CommandBinding{}, err
	}
	b, err := h.Binding(p)
	return otpAuthorityScope(ctx, h.state.work, b.Command, err)
}

func (h OTPReservationWork) authorityScope(ctx context.Context, p OTPReservationContributor) (Work, identity.CommandBinding, error) {
	if err := h.usable(); err != nil {
		return Work{}, identity.CommandBinding{}, err
	}
	b, err := h.Binding(p)
	return otpAuthorityScope(ctx, h.state.work, b.Command, err)
}

func (h OTPApplyWork) authorityScope(ctx context.Context, p OTPReservationContributor) (Work, identity.CommandBinding, error) {
	if err := h.state.usable(otpCheck); err != nil {
		return Work{}, identity.CommandBinding{}, err
	}
	b, err := h.Binding(p)
	return otpAuthorityScope(ctx, h.state.reservation.work, b.Command, err)
}

func (h OTPFinalizeWork) authorityScope(ctx context.Context, p OTPReservationContributor) (Work, identity.CommandBinding, error) {
	if err := h.state.usable(otpFinalize); err != nil {
		return Work{}, identity.CommandBinding{}, err
	}
	b, err := h.Binding(p)
	return otpAuthorityScope(ctx, h.state.reservation.work, b.Command, err)
}

// RequireActiveDirectoryAuthority compares original command-bound global and
// tenant epochs under primary share locks. Only the exact live OTP owner may
// call; any denial poisons the denial transaction even if ignored. Expectations
// must come from authenticated frozen intent, not newly observed versions.
// It creates no proof, session/pre-auth authority or renewable validity lease.
func (h OTPAttemptWork) RequireActiveDirectoryAuthority(ctx context.Context, p OTPAttemptContributor, expected DirectoryAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveDirectoryAuthority(ctx, b, expected))
}

// RequireActiveCredential checks exact original user/identifier/credential
// epochs and credential eligibility in the denial transaction. Expiry uses
// primary time after locks; zero time accompanies denial. Failures poison live
// Work. Success is neither authentication nor session/pre-auth authority.
func (h OTPAttemptWork) RequireActiveCredential(ctx context.Context, p OTPAttemptContributor, expected CredentialAdmission) (time.Time, error) {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return time.Time{}, err
	}
	now, err := w.requireActiveCredential(ctx, b, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, w, err)
	}
	return now, nil
}

// RequireActiveUserAuthorization compares the frozen effective user's epoch
// through the existing authorization owner. It never chooses actor identity,
// decides policy or refreshes proof. All live invocation failures poison Work.
func (h OTPAttemptWork) RequireActiveUserAuthorization(ctx context.Context, p OTPAttemptContributor, expected UserAuthorizationAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return w.requireActiveUserAuthorization(ctx, b, expected)
}

// RequireActiveDirectoryAuthority checks frozen directory epochs during exact
// owner reserve/rebind. Semantics and denial poisoning match OTPAttemptWork;
// original authority must not be refreshed during successor takeover.
func (h OTPReservationWork) RequireActiveDirectoryAuthority(ctx context.Context, p OTPReservationContributor, expected DirectoryAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveDirectoryAuthority(ctx, b, expected))
}

// RequireActiveCredential checks frozen credential eligibility during exact
// owner reserve/rebind, with primary time after locks and zero time on denial.
// Failures poison Work; success neither reserves an OTP nor authenticates.
func (h OTPReservationWork) RequireActiveCredential(ctx context.Context, p OTPReservationContributor, expected CredentialAdmission) (time.Time, error) {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return time.Time{}, err
	}
	now, err := w.requireActiveCredential(ctx, b, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, w, err)
	}
	return now, nil
}

// RequireActiveUserAuthorization checks the frozen effective user's epoch
// during exact owner reserve/rebind. It uses the existing owner, poisons live
// Work on failure and makes no policy decision or freshness renewal.
func (h OTPReservationWork) RequireActiveUserAuthorization(ctx context.Context, p OTPReservationContributor, expected UserAuthorizationAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return w.requireActiveUserAuthorization(ctx, b, expected)
}

// RequireActiveDirectoryAuthority checks original directory epochs under locks
// in the protected transaction. Only the live exact owner may call; failures
// poison Work. This does not establish session/pre-auth authority or consume OTP.
func (h OTPApplyWork) RequireActiveDirectoryAuthority(ctx context.Context, p OTPReservationContributor, expected DirectoryAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveDirectoryAuthority(ctx, b, expected))
}

// RequireActiveCredential checks original credential eligibility under locks in
// the protected transaction. Primary time is not a validity lease; denial
// returns zero time and poisons Work, including an ignored error.
func (h OTPApplyWork) RequireActiveCredential(ctx context.Context, p OTPReservationContributor, expected CredentialAdmission) (time.Time, error) {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return time.Time{}, err
	}
	now, err := w.requireActiveCredential(ctx, b, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, w, err)
	}
	return now, nil
}

// RequireActiveUserAuthorization checks the original user's authorization epoch
// through the existing owner in the protected transaction. It is not a policy
// decision. Failure poisons Work; all other applicable dimensions remain required.
func (h OTPApplyWork) RequireActiveUserAuthorization(ctx context.Context, p OTPReservationContributor, expected UserAuthorizationAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return w.requireActiveUserAuthorization(ctx, b, expected)
}

// RequireActiveDirectoryAuthority rechecks frozen directory epochs before
// terminal finalization in the protected transaction. Failure poisons Work.
// Returned handles deny without affecting later phases. Release deliberately
// has no such gate: proven noncommit must permit release after revocation.
func (h OTPFinalizeWork) RequireActiveDirectoryAuthority(ctx context.Context, p OTPReservationContributor, expected DirectoryAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveDirectoryAuthority(ctx, b, expected))
}

// RequireActiveCredential rechecks frozen credential eligibility before
// terminal finalization, using primary time after locks. Denial returns zero
// time and poisons Work. It never renews original validity or issues a session.
func (h OTPFinalizeWork) RequireActiveCredential(ctx context.Context, p OTPReservationContributor, expected CredentialAdmission) (time.Time, error) {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return time.Time{}, err
	}
	now, err := w.requireActiveCredential(ctx, b, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, w, err)
	}
	return now, nil
}

// RequireActiveUserAuthorization rechecks the original user's epoch through
// its existing owner before terminal finalization. Failure poisons Work; it
// never changes epochs, chooses an actor or substitutes for a policy decision.
func (h OTPFinalizeWork) RequireActiveUserAuthorization(ctx context.Context, p OTPReservationContributor, expected UserAuthorizationAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return w.requireActiveUserAuthorization(ctx, b, expected)
}

// RequireActiveUserAuthority locks the command-bound primary user and compares
// active status and all three original security epochs without requiring a
// credential reference. Only the exact live owner may call; denial poisons Work
// even if ignored. It never refreshes intent or grants authentication authority.
// Credential-bearing workflows must additionally check their exact credential.
func (h OTPAttemptWork) RequireActiveUserAuthority(ctx context.Context, p OTPAttemptContributor, expected UserAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveUserAuthority(ctx, b, expected))
}

// RequireActiveUserAuthority checks original user security epochs during exact
// owner reserve/rebind. Semantics match OTPAttemptWork; takeover cannot renew
// expectations. Locks last until transaction end and live denial poisons Work.
func (h OTPReservationWork) RequireActiveUserAuthority(ctx context.Context, p OTPReservationContributor, expected UserAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveUserAuthority(ctx, b, expected))
}

// RequireActiveUserAuthority checks original user security epochs under primary
// locks in the protected transaction without a credential reference. Live
// denial poisons Work. Success alone neither authenticates nor consumes OTP.
func (h OTPApplyWork) RequireActiveUserAuthority(ctx context.Context, p OTPReservationContributor, expected UserAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveUserAuthority(ctx, b, expected))
}

// RequireActiveUserAuthority rechecks original user security epochs before
// finalization; live denial poisons Work. Returned handles cannot poison later
// invocations. Proven noncommit release intentionally has no such live gate.
func (h OTPFinalizeWork) RequireActiveUserAuthority(ctx context.Context, p OTPReservationContributor, expected UserAuthorityAdmission) error {
	w, b, err := h.authorityScope(ctx, p)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveUserAuthority(ctx, b, expected))
}
