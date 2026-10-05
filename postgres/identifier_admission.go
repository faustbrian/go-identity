package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// IdentifierAdmissionContributor performs primary session and applicable owner
// checks for one frozen self-user identifier command. It is a read-only role,
// not a durable effect owner: recovery never asks it to attest mutation outcome.
// Implementations must compare the frozen command, close rows, use bounded
// primary reads, and never retain Work, perform network calls or close a
// transaction. A successful check does not authenticate or authorize by itself.
type IdentifierAdmissionContributor interface {
	Contributor
	CheckIdentifier(context.Context, IdentifierAdmissionWork) error
}

func identifierAdmissionDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}

type identifierAdmissionState struct {
	work          Work
	participant   IdentifierAdmissionContributor
	command       identity.IdentifierCommand
	final, active bool
}

// IdentifierAdmissionWork borrows the sole coordinator's transaction only for
// an exact registered check invocation. It permits bounded queries and current
// kernel eligibility checks, but no Exec or transaction closure. Copies share
// serial invocation lifetime; zero and retained handles deny. Errors on a live
// invocation poison the original Work even when ignored by the participant.
type IdentifierAdmissionWork struct{ state *identifierAdmissionState }

// Format hides command, proof and transaction correlation.
func (IdentifierAdmissionWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.IdentifierAdmissionWork(redacted)"))
}

// MarshalJSON rejects export of invocation authority.
func (IdentifierAdmissionWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit export of invocation authority.
func (IdentifierAdmissionWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h IdentifierAdmissionWork) usable() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.usable()
}

func (h IdentifierAdmissionWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}

// Command returns the complete frozen command and whether this is the terminal
// temporal recheck, only to the exact selected comparable participant. Neither
// phase renews authentication freshness or original session/proof expiry.
func (h IdentifierAdmissionWork) Command(p IdentifierAdmissionContributor) (identity.IdentifierCommand, bool, error) {
	if err := h.usable(); err != nil {
		return identity.IdentifierCommand{}, false, err
	}
	if !sameParticipant(p, h.state.participant) {
		return identity.IdentifierCommand{}, false, h.deny()
	}
	return h.state.command, h.state.final, nil
}

// Query executes a bounded trusted primary query. Rows must close before the
// callback returns. This is not a sandbox for arbitrary caller SQL.
func (h IdentifierAdmissionWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	rows, err := h.state.work.Query(ctx, sql, args...)
	return rows, h.failure(ctx, err)
}

// DatabaseTime samples primary time without creating or renewing a validity lease.
func (h IdentifierAdmissionWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.DatabaseTime(ctx)
	return now, h.failure(ctx, err)
}

// RequireActiveCredential uses the existing kernel credential owner checks and
// retains its share locks until the original transaction closes.
func (h IdentifierAdmissionWork) RequireActiveCredential(ctx context.Context, p IdentifierAdmissionContributor, e CredentialAdmission) (time.Time, error) {
	c, _, err := h.Command(p)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.requireActiveCredential(ctx, c.Binding, e)
	return now, h.failure(ctx, err)
}

// RequireActiveDirectoryAuthority checks exact configured global and tenant epochs.
func (h IdentifierAdmissionWork) RequireActiveDirectoryAuthority(ctx context.Context, p IdentifierAdmissionContributor, e DirectoryAuthorityAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveDirectoryAuthority(ctx, c.Binding, e))
}

// RequireActiveUserAuthorization borrows the existing authorization owner's
// implementation; it neither decides policy nor claims organization authority.
func (h IdentifierAdmissionWork) RequireActiveUserAuthorization(ctx context.Context, p IdentifierAdmissionContributor, e UserAuthorizationAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveUserAuthorization(ctx, c.Binding, e))
}

// Work's lower-level cursor guard is retryable for trusted owners. Admission
// cannot forget a denied check merely because the participant closes its cursor.
func (h IdentifierAdmissionWork) failure(ctx context.Context, err error) error {
	if err != nil {
		return h.state.work.fail(ctx, err)
	}
	return nil
}

func (c *Coordinator) runIdentifierAdmission(ctx context.Context, w Work, command identity.Command, final bool) (err error) {
	if !c.owns(w) {
		return invalidWork()
	}
	if err = w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	r := w.state.execution.reservation
	p := r.plan
	spec, ok := command.ChangeIdentifier()
	if !ok || p == nil || p.identifierAdmission == nil || spec.Binding != p.binding || spec.Binding != w.state.binding {
		return w.fail(ctx, invalidPlan())
	}
	q, e := prepareClaim(command, c.keys.retained[c.keys.current])
	if e != nil || !bytes.Equal(q.canonical, r.request.canonical) {
		return w.fail(ctx, invalidPlan())
	}
	participant, ok := p.identifierAdmission.contributor.(IdentifierAdmissionContributor)
	if !ok || !sameParticipant(participant, participant) {
		return w.fail(ctx, invalidPlan())
	}
	s := &identifierAdmissionState{work: w, participant: participant, command: spec, final: final, active: true}
	defer func() {
		s.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	err = participant.CheckIdentifier(ctx, IdentifierAdmissionWork{state: s})
	if err != nil {
		_, _, _, safe := abortClassification(err)
		return w.fail(ctx, safe)
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return w.usable()
}
