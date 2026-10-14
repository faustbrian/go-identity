package mfapostgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// LockedRecoveryAttempt borrows actual recovery comparison custody exclusively
// during one native denial callback. A successful comparison is not a factor
// proof: it permits neither code burn nor session issuance. Copies share the
// serial-use lifetime and one provisional denial charge; returned handles deny.
type LockedRecoveryAttempt struct{ custody func() *lockedRecoveryAttempt }
type lockedRecoveryAttempt struct {
	work         kernel.MFARecoveryAttemptWork
	owner        kernel.MFARecoveryAttemptContributor
	binding      kernel.MFARecoveryAttemptBinding
	continuation mfa.PartialAuthContinuation
	set          RecoverySetMetadata
	matched      bool
	spent        bool
}

// Format redacts borrowed callback authority and comparison results.
func (LockedRecoveryAttempt) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedRecoveryAttempt(redacted)"))
}

// MarshalJSON rejects borrowed custody export.
func (LockedRecoveryAttempt) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects borrowed custody export.
func (LockedRecoveryAttempt) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// MatchedSet returns non-secret preparation metadata only for this same live
// callback's unused matching code. Zero, wrong-code, spent and returned custody
// deny. The projection may plan the original prospective session, but is not
// authentication or permission to consume a code/child. Protected completion
// must independently compare the original code and recheck the exact set/factor
// versions in its own locked Work; no caller-selected factor is substituted.
func (a LockedRecoveryAttempt) MatchedSet() (RecoverySetMetadata, error) {
	if a.custody == nil {
		return RecoverySetMetadata{}, invalidAuthority()
	}
	s := a.custody()
	if s == nil || !s.matched || s.spent {
		return RecoverySetMetadata{}, invalidAuthority()
	}
	b, err := s.work.Binding(s.owner)
	if err != nil || b != s.binding {
		return RecoverySetMetadata{}, invalidAuthority()
	}
	return s.set, nil
}

// CompareRecoveryAttempt locks original account/factor/continuation authority,
// then bounded active sets and compares the unchanged native opaque recovery
// input against digest-only custody. The owner must first fence current policy,
// original primary/browser and protected risk. Missing keys or corrupt sets fail
// closed. No external callback, generation, burn, session or transaction occurs.
// A false match can be charged only through RecordRecoveryAttemptDenial; true
// must roll back this probe and be reverified in protected completion.
func CompareRecoveryAttempt(ctx context.Context, w kernel.MFARecoveryAttemptWork, owner kernel.MFARecoveryAttemptContributor, keys RecoveryVerificationKeys) (LockedRecoveryAttempt, bool, error) {
	if ctx == nil {
		return LockedRecoveryAttempt{}, false, invalidAuthority()
	}
	b, err := w.Binding(owner)
	if err != nil {
		return LockedRecoveryAttempt{}, false, err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return LockedRecoveryAttempt{}, false, err
	}
	code, ok := command.RecoveryCode()
	if !ok {
		return LockedRecoveryAttempt{}, false, invalidAuthority()
	}
	c, _, row, matched, err := lockRecovery(ctx, recoveryWorkStore(w.Query, w.Exec), b, keys, code)
	if err != nil {
		return LockedRecoveryAttempt{}, false, err
	}
	s := &lockedRecoveryAttempt{work: w, owner: owner, binding: b, continuation: c, set: row.set, matched: matched}
	return LockedRecoveryAttempt{custody: func() *lockedRecoveryAttempt { return s }}, matched, nil
}

// RecordRecoveryAttemptDenial charges one shared attempt only after this same
// live callback's actual comparison found no unused matching code. Correct,
// foreign, zero, spent or returned custody denies. The coordinator commits this
// charge with protected risk, denial audit and original journal receipt; any
// error must abort. It does not consume the code/child or advance TOTP replay.
func RecordRecoveryAttemptDenial(ctx context.Context, w kernel.MFARecoveryAttemptWork, owner kernel.MFARecoveryAttemptContributor, a LockedRecoveryAttempt) error {
	if ctx == nil || a.custody == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := a.custody()
	if s == nil || s.spent || s.matched || w != s.work {
		return invalidAuthority()
	}
	b, err := w.Binding(owner)
	if err != nil || b != s.binding {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := spendMFAAttempt(ctx, recoveryWorkStore(w.Query, w.Exec).sql, s.continuation, now, "recovery-code"); err != nil {
		return err
	}
	s.spent = true
	return nil
}
