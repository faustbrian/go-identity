package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// CapabilityReservationContributor supplies the two atomic pre-domain phases
// for capability.one-use v1. Only Coordinator invokes these methods. Reserve
// locks an already-issued exact input and binds command/fingerprint/generation;
// it must not insert missing capability state or consume a use. Rebind must CAS
// an existing reserved row from exactly PreviousGeneration to Generation under
// the same command/fingerprint. Missing, terminal or mismatched rows fail without
// changing state. Both phases participate in the command reservation transaction.
// Implementations must validate Binding with their own registered identity before
// SQL, use primary time for expiry,
// close rows, return redacted errors and never retain Work, invoke caller hooks,
// perform network I/O or begin/close another transaction. This open interface
// grants no invocation authority. Domain/finalization phases remain separate.
type CapabilityReservationContributor interface {
	Contributor
	ReserveCapability(context.Context, CapabilityReservationWork) error
	RebindCapability(context.Context, CapabilityReservationWork) error
}

func capabilityReservationParticipant(c Contributor) (CapabilityReservationContributor, bool) {
	p, ok := c.(CapabilityReservationContributor)
	return p, ok && !nilContributor(p) && reflect.TypeOf(p).Comparable()
}

// CapabilityReservationBinding is an owned scalar snapshot of one invocation.
// Fingerprint is the authoritative retained-key command fingerprint, not a
// caller replacement. Generation is positive. PreviousGeneration is zero only
// for Reserve; Rebind requires its exact positive predecessor. Plan is the
// frozen capability input, never a proof of current authorization. No bearer
// bytes or cryptographic key material are included. Diagnostics are redacted.
// Release also uses this snapshot: proven live-owner rollback preserves the
// generation; recovery release requires the exact successor generation.
type CapabilityReservationBinding struct {
	Command                        identity.CommandBinding
	Plan                           CapabilityPlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

// Format redacts retained command and proof correlation metadata.
func (CapabilityReservationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityReservationBinding(redacted)"))
}

// MarshalJSON prevents export of retained correlation metadata.
func (CapabilityReservationBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// CapabilityReservationWork is a coordinator-created, invocation-bound SQL
// capability. There is no constructor, raw driver, closure or Work escape hatch.
// Copies share lifetime and expire when the callback returns, including panic.
// Serial use only; returned rows must be closed before return. Existing Work
// parameter/result/time budgets apply; earlier deadlines win. Zero is invalid.
type CapabilityReservationWork struct{ state *capabilityReservationState }

type capabilityReservationState struct {
	coordinator        *Coordinator
	work               Work
	plan               *admittedKernelPlan
	previousGeneration uint64
	active             bool
	contributor        CapabilityReservationContributor
	releaseProof       capabilityReleaseProof
}

// Format hides the retained transaction and participant state.
func (CapabilityReservationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityReservationWork(redacted)"))
}

// MarshalJSON rejects serialization of invocation authority.
func (CapabilityReservationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

func (w CapabilityReservationWork) usable() error {
	s := w.state
	if s == nil || s.releaseProof != 0 || s.previousGeneration != 0 && (s.previousGeneration == ^uint64(0) || s.work.state == nil || s.work.state.generation != s.previousGeneration+1) {
		return invalidWork()
	}
	return s.usable()
}

func (s *capabilityReservationState) usable() error {
	if s == nil || !s.active || s.coordinator == nil || s.plan == nil || s.plan.capability == nil || s.work.state == nil || s.plan.belongsTo(s.coordinator.registry) != nil || s.work.state.registry != s.plan.registry || s.work.state.binding != s.plan.binding || s.plan.fingerprint == ([32]byte{}) || s.work.state.generation == 0 {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding returns an owned declaration after checking invocation lifetime and
// exact registered contributor identity. Comparable immutable values use value
// identity; pointer implementations use instance identity. Nil, noncomparable or
// foreign implementations fail before participant SQL.
func (w CapabilityReservationWork) Binding(contributor CapabilityReservationContributor) (CapabilityReservationBinding, error) {
	if err := w.usable(); err != nil {
		return CapabilityReservationBinding{}, err
	}
	return w.state.binding(contributor)
}

func (s *capabilityReservationState) binding(contributor CapabilityReservationContributor) (CapabilityReservationBinding, error) {
	// Comparable values have stable value identity; pointers retain instance
	// identity. Noncomparable implementations cannot prove identity and fail closed.
	if nilContributor(contributor) || !reflect.TypeOf(contributor).Comparable() || contributor != s.contributor {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: s.plan.binding, Plan: *s.plan.capability, Fingerprint: s.plan.fingerprint, Generation: s.work.state.generation, PreviousGeneration: s.previousGeneration}, nil
}

// Exec executes one trusted participant statement, never transaction closure.
func (w CapabilityReservationWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns bounded invocation-owned rows; close/drain them before return.
func (w CapabilityReservationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without renewing the original lease/lifetime.
func (w CapabilityReservationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) reserveCapability(ctx context.Context, tx pgx.Tx, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (err error) {
	if p.capability == nil {
		return nil
	}
	var operation *identity.FeatureOperation
	if p.feature != nil {
		operation = &p.feature.Operation
	}
	if p.belongsTo(c.registry) != nil || j.disposition != journalOwned || !bytes.Equal(q.safeFields, commandSafeFields(p.binding, operation)) {
		return invalidPlan()
	}
	var contributor CapabilityReservationContributor
	for _, entry := range p.contributors {
		if entry.descriptor.Owner == "capability/postgres" && entry.descriptor.ContractID == "capability.one-use" {
			contributor, _ = capabilityReservationParticipant(entry.contributor)
		}
	}
	if contributor == nil {
		return invalidPlan()
	}
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return err
	}
	work, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	work.state.registry = c.registry.state
	state := &capabilityReservationState{coordinator: c, work: work, plan: p, previousGeneration: j.previousGeneration, active: true, contributor: contributor}
	defer func() {
		state.active = false
		invalidateWork(work)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err = configureKernelWork(ctx, work); err != nil {
		return err
	}
	handle := CapabilityReservationWork{state: state}
	if err = handle.usable(); err != nil {
		return err
	}
	if j.previousGeneration == 0 {
		err = contributor.ReserveCapability(ctx, handle)
	} else {
		err = contributor.RebindCapability(ctx, handle)
	}
	if err != nil {
		return work.fail(ctx, err)
	}
	if work.state.rows != nil {
		return identity.UnavailableError{}
	}
	return work.usable()
}

func capabilityReservationCommand(command identity.Command, plan CommandPlan) bool {
	spec, ok := command.ChangeIdentifier()
	if !ok || plan.Capability == nil || plan.Lifecycle == nil {
		return false
	}
	proof := spec.Proof.Payload()
	envelope := spec.Proof.EnvelopeDigest()
	p := plan.Capability
	// The declared storage fingerprint must name this authenticated envelope,
	// not another issued artifact with identical payload identity/use bounds.
	// Historical plan decoding remains structural and preserves original bytes.
	return envelope != ([32]byte{}) && p.ProofFingerprint == envelope && p.CapabilityID == proof.ID && p.MaxUses == proof.MaxUses && p.ExpiresAt == proof.ExpiresAt && plan.Lifecycle.BeforeVersion == spec.Change.ExpectedIdentifierVersion && spec.Change.ExpectedIdentifierVersion != ^uint64(0) && plan.Lifecycle.AfterVersion == spec.Change.ExpectedIdentifierVersion+1
}
