package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// CapabilityIssuanceContributor owns capability.issuance v1 persistence and
// recovery, not the originating mutation or its transaction. Validation is
// bounded and pure. Persistence must match the staged authenticated Grants to
// their exact original envelope fingerprints and independently keyed replay
// digests before inserting absent issued state. It must retain original command,
// fingerprint and generation separately from subsequent consumption binding;
// mismatched or terminal records must never be replaced/reactivated. No bearer,
// signer, network operation, caller hook or private transaction belongs here.
// Methods support concurrent independent commands; phase handles are serial-use.
type CapabilityIssuanceContributor interface {
	RecoveryContributor
	ValidateCapabilityIssuance(identity.CommandBinding, CapabilityIssuancePlan) error
	PersistCapabilityIssuance(context.Context, CapabilityIssuanceWork) error
}

// CapabilityIssuanceBinding is original-command metadata, never a proof of
// authorization or committed outcome. PreviousGeneration is zero in persistence;
// recovery supplies the original previous generation and the new fenced owner.
// Plan is an owned copy. Neither generation changes the signed credential expiry.
type CapabilityIssuanceBinding struct {
	Command                        identity.CommandBinding
	Plan                           CapabilityIssuancePlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

// Format hides retained correlation and signed-envelope metadata.
func (CapabilityIssuanceBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityIssuanceBinding(redacted)"))
}

// MarshalJSON rejects serialization of retained issuance bindings.
func (CapabilityIssuanceBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

type workIssuance struct {
	plan       *CapabilityIssuancePlan
	grants     []capability.Grant
	staged     []bool
	invocation *capabilityIssuanceState
	persisted  bool
}

type capabilityIssuanceState struct {
	work   Work
	owner  CapabilityIssuanceContributor
	active bool
}

// CapabilityIssuanceWork is granted only during the exact enlisted owner's
// original-command persistence invocation. There is no constructor, general
// Work escape hatch or transaction closure. Aliases expire when the invocation
// returns, including panic. Close every row before return; existing Work bounds
// and earlier deadlines apply. A successful insert remains provisional.
type CapabilityIssuanceWork struct{ state *capabilityIssuanceState }

// Format hides invocation custody and transaction state.
func (CapabilityIssuanceWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityIssuanceWork(redacted)"))
}

// MarshalJSON rejects serialization of phase authority.
func (CapabilityIssuanceWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

func (w CapabilityIssuanceWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.work.state == nil || s.work.state.issuance == nil || s.work.state.issuance.invocation != s || s.work.state.execution == nil || s.work.state.execution.reservation == nil {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding supplies an owned snapshot only to the currently invoked exact owner.
func (w CapabilityIssuanceWork) Binding(p CapabilityIssuanceContributor) (CapabilityIssuanceBinding, error) {
	if w.usable() != nil || !sameParticipant(p, w.state.owner) {
		return CapabilityIssuanceBinding{}, invalidWork()
	}
	s := w.state.work.state
	return CapabilityIssuanceBinding{Command: s.binding, Plan: *cloneCapabilityIssuancePlan(s.issuance.plan), Fingerprint: s.execution.reservation.plan.fingerprint, Generation: s.generation}, nil
}

// Grants returns immutable authenticated authority only during the owner phase.
// Payload accessors remain defensive copies. These grants carry no bearer bytes
// and do not prove current authorization or committed issuance. The owner must
// verify the original-envelope/replay bindings; metadata equality alone is not
// sufficient. Returning the slice conveys no SQL or future invocation authority.
func (w CapabilityIssuanceWork) Grants(p CapabilityIssuanceContributor) ([]capability.Grant, error) {
	if _, err := w.Binding(p); err != nil {
		return nil, err
	}
	return append([]capability.Grant(nil), w.state.work.state.issuance.grants...), nil
}

// Exec executes bounded participant SQL, never transaction closure.
func (w CapabilityIssuanceWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns invocation-owned bounded rows; close them before return.
func (w CapabilityIssuanceWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without extending the lease or credential.
func (w CapabilityIssuanceWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

// StageCapabilityIssuanceFor stages one authenticated, subject-bound grant for
// the exact declared issuer, not a caller-authored proof projection. Index is
// the frozen plan position. Grant identity, purpose, tenant, subject, exclusive
// expiry and single-use maximum must match. The issuer remains responsible for
// cryptographic envelope/replay provenance and workflow policy.
// A declared RegistrationUserID instead selects only this Work's successfully
// created anonymous-signup user for identifier verification; it never changes
// the original command binding or permits arbitrary subject selection.
// ResetRecipientUserID instead requires this invocation's successful primary
// recipient/credential fence and matching original reset scope. Neither target
// alone proves current factor eligibility or complete workflow authorization.
// MagicLinkRecipientUserID likewise requires the exact magic-link invocation's
// primary verified-email fence and signed original identifier/security scope.
// MFAContinuationUserID selects only the closed challenge owner's subject after
// provisional primary consumption, with exact signed continuation scope/time.
// No bearer is exposed or stored here; encrypted delivery must be staged by
// its registered owner. Failure poisons this command. Foreign owners are denied
// before staging. Work and aliases must remain serial-use.
func (w Work) StageCapabilityIssuanceFor(p CapabilityIssuanceContributor, index uint16, grant capability.Grant) error {
	if err := w.usable(); err != nil {
		return err
	}
	d := w.state.issuance
	if w.state.magicLinkRequestAccepted {
		return w.fail(w.state.ctx, invalidWork())
	}
	if d == nil || d.invocation != nil || d.persisted || w.state.execution == nil || w.state.execution.reservation == nil {
		return invalidWork()
	}
	owned := false
	for _, e := range w.state.execution.reservation.plan.contributors {
		if e.descriptor == d.plan.Contributor {
			owned = sameParticipant(p, e.contributor)
			break
		}
	}
	if !owned {
		return invalidWork()
	}
	if int(index) >= len(d.plan.Grants) || d.staged[index] {
		return w.fail(w.state.ctx, invalidWork())
	}
	v, payload := d.plan.Grants[index], grant.Payload()
	subject := w.state.binding.UserID
	if w.state.binding.OperationID == organizationInvitationSendOperation().OperationID || w.state.binding.OperationID == organizationInvitationResendOperation().OperationID {
		var err error
		subject, err = organizationInvitationIssuanceSubject(w.state, w.state.execution.reservation.plan.snapshot(), payload)
		if err != nil {
			return w.fail(w.state.ctx, err)
		}
	}
	if d.plan.RegistrationUserID != "" {
		created := w.state.registrationUser
		if !validRegistrationIssuance(w.state.binding, w.state.execution.reservation.plan.snapshot()) || created == nil || created.ID != d.plan.RegistrationUserID || created.Validate(w.state.binding.TenantID) != nil || created.Status != identity.StatusActive || created.Version != 1 {
			return w.fail(w.state.ctx, invalidWork())
		}
		subject = created.ID
	}
	if d.plan.ResetRecipientUserID != "" {
		var err error
		subject, err = resetIssuanceSubject(w.state, w.state.execution.reservation.plan.snapshot(), payload)
		if err != nil {
			return w.fail(w.state.ctx, err)
		}
	}
	if d.plan.MagicLinkRecipientUserID != "" {
		var err error
		subject, err = magicLinkIssuanceSubject(w.state, w.state.execution.reservation.plan.snapshot(), payload)
		if err != nil {
			return w.fail(w.state.ctx, err)
		}
	}
	if d.plan.MFAContinuationUserID != "" {
		var err error
		subject, err = magicLinkMFAIssuanceSubject(w, payload)
		if err != nil {
			return w.fail(w.state.ctx, err)
		}
	}
	if payload.ID != v.CapabilityID || payload.Operation != string(v.Purpose) || payload.Tenant != string(w.state.binding.TenantID) || payload.Subject != string(subject) || payload.Subject == "" || payload.Bearer || payload.MaxUses != v.MaxUses || payload.ExpiresAt != v.ExpiresAt {
		return w.fail(w.state.ctx, invalidWork())
	}
	// Grant is opaque, copied authority already validated by capability.Verify
	// under its owner's explicit limits. Reapplying unrelated defaults here
	// rejects valid profiles without strengthening the authenticated boundary.
	// Bind the complete verified envelope to the frozen declaration instead;
	// the enlisted issuer independently rechecks its selected policy at persist.
	if grant.EnvelopeDigest() == ([32]byte{}) || grant.EnvelopeDigest() != v.ProofFingerprint {
		return w.fail(w.state.ctx, invalidWork())
	}
	d.grants[index], d.staged[index] = grant, true
	return nil
}

// CapabilityIssuanceBinding returns frozen original-command metadata only to
// this exact issuer during its recovery phase. It grants primary evidence reads,
// not signing, issuing, release, bearer retrieval or command terminalization.
func (w RecoveryWork) CapabilityIssuanceBinding(p CapabilityIssuanceContributor) (CapabilityIssuanceBinding, error) {
	if w.usable() != nil || w.state.plan.issuance == nil || w.state.entry.descriptor != w.state.plan.issuance.Contributor || !sameParticipant(w.state.entry.contributor, p) || w.state.work.state.execution == nil || w.state.work.state.execution.reservation == nil {
		return CapabilityIssuanceBinding{}, invalidWork()
	}
	s := w.state.work.state
	return CapabilityIssuanceBinding{Command: w.state.plan.binding, Plan: *cloneCapabilityIssuancePlan(w.state.plan.issuance), Fingerprint: w.state.plan.fingerprint, Generation: s.generation, PreviousGeneration: s.execution.reservation.journal.previousGeneration}, nil
}

func validateIssuanceContributor(b identity.CommandBinding, p *CapabilityIssuancePlan, entries []registeredContributor) (err error) {
	if p == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	for _, e := range entries {
		if e.descriptor == p.Contributor {
			owner, ok := e.contributor.(CapabilityIssuanceContributor)
			if !ok || !sameParticipant(owner, owner) || owner.ValidateCapabilityIssuance(b, *cloneCapabilityIssuancePlan(p)) != nil {
				return invalidPlan()
			}
			return nil
		}
	}
	return invalidPlan()
}

func issuanceFresh(w Work) error {
	if w.state.issuance == nil {
		return nil
	}
	now, err := w.DatabaseTime(w.state.ctx)
	if err != nil {
		return err
	}
	for _, g := range w.state.issuance.plan.Grants {
		if !now.Before(g.ExpiresAt) {
			return invalidWork()
		}
	}
	return nil
}

func (c *Coordinator) persistCapabilityIssuance(w Work) (err error) {
	d := w.state.issuance
	if d == nil {
		return nil
	}
	if w.state.registrationAccepted || w.state.magicLinkRequestAccepted {
		if !neutralEffectsDeclared(w) || d.persisted {
			return invalidWork()
		}
		for _, staged := range d.staged {
			if staged {
				return invalidWork()
			}
		}
		return nil
	}
	if d.persisted || len(d.grants) != len(d.plan.Grants) {
		return invalidWork()
	}
	for _, staged := range d.staged {
		if !staged {
			return invalidWork()
		}
	}
	if err := issuanceFresh(w); err != nil {
		return err
	}
	for _, e := range w.state.execution.reservation.plan.contributors {
		if e.descriptor != d.plan.Contributor {
			continue
		}
		owner, ok := e.contributor.(CapabilityIssuanceContributor)
		if !ok {
			return invalidWork()
		}
		s := &capabilityIssuanceState{work: w, owner: owner, active: true}
		d.invocation = s
		defer func() {
			s.active = false
			d.invocation = nil
			if recover() != nil {
				err = identity.UnavailableError{}
			}
		}()
		if err := owner.PersistCapabilityIssuance(w.state.ctx, CapabilityIssuanceWork{state: s}); err != nil {
			_, _, _, safe := abortClassification(err)
			return safe
		}
		if w.state.rows != nil || w.usable() != nil {
			return identity.UnavailableError{}
		}
		d.persisted = true
		return nil
	}
	return invalidWork()
}
