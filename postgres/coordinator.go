package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// CoordinatorConfig supplies finite primary-operation and lease budgets and
// retained fingerprint keys. Durations must be positive, at most one minute;
// LeaseDuration must be microsecond-exact. The current positive key version
// must exist in the 1..32 retained nonzero 32-byte keys. Retain old keys while
// their command claims exist. Treat keys as secrets; the constructor copies
// the map. Do not mutate caller-owned configuration during construction.
type CoordinatorConfig struct {
	MaximumDuration              time.Duration
	LeaseDuration                time.Duration
	CurrentFingerprintKeyVersion uint32
	RetainedFingerprintKeys      map[uint32][32]byte
	// QueryPolicy enables authorized primary receipt lookup. Nil disables it.
	// The policy is copied; its dependencies must support concurrent calls.
	QueryPolicy *CommandQueryPolicy
}

// Format prevents diagnostic formatting from exposing fingerprint keys.
func (CoordinatorConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CoordinatorConfig(redacted)"))
}

// MarshalJSON rejects configuration serialization rather than exposing keys.
func (CoordinatorConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "coordinator_configuration"}
}

// Coordinator owns bounded command reservation transactions against a
// caller-owned primary pool and immutable registry. It starts no goroutines
// and never closes the pool. Concurrent reservations are supported. This
// incremental implementation admits creation and field-update mutation with
// required audit and lifecycle declarations. Begin, the enlisted Repository,
// Commit/Abort and the owned service compositions control execution. Recovery
// supports conservative creation/profile reconciliation; other recovery profiles
// and deadline alerting remain under development. Reservation is
// bookkeeping, never proof of a user mutation or audit/outbox persistence.
type Coordinator struct {
	pool                           *database.Pool
	registry                       *ContributorRegistry
	maximumDuration, leaseDuration time.Duration
	keys                           claimKeys
	queryPolicy                    *CommandQueryPolicy
	commandRead                    func(context.Context, identity.CommandID) (commandObservation, error)
}

// Format prevents diagnostics from exposing retained keys and pool settings.
func (Coordinator) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.Coordinator(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition and secret keys.
func (Coordinator) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

// NewCoordinator validates and copies composition without I/O. Migrate the
// primary database before reservation. Registry implementations are trusted
// typed adapters; no contributor method or caller callback runs here or in
// reservation transactions. Invalid configuration returns a redacted error.
func NewCoordinator(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig) (*Coordinator, error) {
	if pool == nil || pool.Raw() == nil || registry == nil || registry.state == nil || !validCoordinatorConfig(config) {
		return nil, coordinatorError()
	}
	keys := claimKeys{current: config.CurrentFingerprintKeyVersion, retained: make(map[uint32][32]byte, len(config.RetainedFingerprintKeys))}
	for version, key := range config.RetainedFingerprintKeys {
		keys.retained[version] = key
	}
	c := &Coordinator{pool: pool, registry: &ContributorRegistry{state: registry.state}, maximumDuration: config.MaximumDuration, leaseDuration: config.LeaseDuration, keys: keys}
	if config.QueryPolicy != nil {
		if !validCommandQueryPolicy(*config.QueryPolicy) {
			return nil, coordinatorError()
		}
		policy := *config.QueryPolicy
		c.queryPolicy = &policy
		c.commandRead = c.readCommand
	}
	return c, nil
}

// Reservation is opaque, generation-bound ownership from a proven durable
// reservation commit. Copies share the private snapshot and single-use state.
// It grants no Work, SQL, closure or independently usable execution authority;
// zero is invalid. It cannot be serialized and diagnostics are redacted.
// Begin consumes it once, including a failed admitted attempt. Retain it only
// for the owning Coordinator; it is not authority to renew the lease.
type Reservation struct{ state *reservationState }

type reservationState struct {
	coordinator *Coordinator
	request     claimRequest
	plan        *admittedKernelPlan
	journal     journalReservation
	owner       [16]byte
	started     atomic.Bool
}

// Format hides command, tenant, lease owner and retained private command data.
func (Reservation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.Reservation(redacted)"))
}

// MarshalJSON rejects serialization of opaque reservation ownership.
func (Reservation) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "reservation"}
}

// PrepareCommandPlan checks the exact typed command binding and registry,
// computes the current-key fingerprint and returns an owned plan snapshot.
// The supplied Digest is replaced. It performs no I/O, reserves nothing and
// supplies no authorization: the identity service must authorize and prepare
// the command before calling the trusted composition adapter. Unsupported
// one-time/cascade command profiles are rejected before any SQL. Mutating
// returned slices affects only that caller's plan; do not mutate inputs during
// the call. A replay is rebound to its stored retained-key fingerprint inside
// ReserveCommand, never assigned a new fingerprint after key rotation.
func (c *Coordinator) PrepareCommandPlan(binding identity.CommandBinding, command identity.Command, plan CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepare(binding, command, plan)
	return snapshot, err
}

func (c *Coordinator) prepare(binding identity.CommandBinding, command identity.Command, plan CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	if c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 {
		return claimRequest{}, CommandPlan{}, nil, coordinatorError()
	}
	// No proof/cascade declaration is inferred from a contributor name. Those
	// command profiles need their typed reservation phases before admission.
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	if !isCreation(command) && !isProfile(command) && !isUpdate(command) || plan.Capability != nil || plan.Lifecycle == nil || len(plan.Contributors) != 3 || len(plan.Audits) != 1 || probe.Validate() != nil {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	if spec, ok := command.UpdateProfile(); ok && (plan.Lifecycle.BeforeVersion != spec.ExpectedVersion || plan.Lifecycle.AfterVersion != spec.ExpectedVersion+1) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	if spec, ok := command.UpdateUser(); ok && (plan.Lifecycle.BeforeVersion != spec.ExpectedVersion || plan.Lifecycle.AfterVersion != spec.ExpectedVersion+1) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		return claimRequest{}, CommandPlan{}, nil, err
	}
	if !validClaim(q, c.keys) || !bytes.Equal(q.safeFields, cborMap(commandScope(binding))) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	snapshot := CommandPlan{Contributors: append([]ContributorDescriptor(nil), plan.Contributors...), Audits: append([]AuditPlan(nil), plan.Audits...)}
	lifecycle := *plan.Lifecycle
	snapshot.Lifecycle = &lifecycle
	fingerprint := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	snapshot.Digest, err = KernelPlanDigest(binding, fingerprint, snapshot)
	if err != nil {
		return claimRequest{}, CommandPlan{}, nil, err
	}
	admitted, err := c.registry.admitKernelPlan(binding, fingerprint, snapshot)
	if err != nil {
		return claimRequest{}, CommandPlan{}, nil, err
	}
	return q, snapshot, admitted, nil
}

// ReserveCommand atomically locks the global ID claim before the scoped
// journal, freezes the complete supported plan and establishes a new or
// expired generation lease. A successful new reservation returns an opaque
// value plus InProgress, never Committed. Live replay returns zero reservation
// and bounded InProgress; exact terminal replay returns its historical receipt,
// not fresh authority. Changed scope/intent/plan returns Conflict. Missing keys,
// historical NULL plans or corrupt history fail closed. Invalid/pre-observation
// or proven-rollback failures return a zero result, not a fabricated durable
// NotCommitted. Any commit-attempt failure or unproven rollback returns Unknown
// with zero reservation; no automatic retry or local rollback after commit.
// Earlier caller deadlines win. All driver diagnostics are redacted. This
// phase performs no domain mutation or participant persistence. It grants no
// proof that required audit/outbox effects have been written.
func (c *Coordinator) ReserveCommand(ctx context.Context, binding identity.CommandBinding, command identity.Command, plan CommandPlan) (Reservation, identity.CommandResult, error) {
	if ctx == nil {
		return Reservation{}, identity.CommandResult{}, coordinatorError()
	}
	q, snapshot, _, err := c.prepare(binding, command, plan)
	if err != nil {
		return Reservation{}, identity.CommandResult{}, err
	}
	if snapshot.Digest != plan.Digest {
		return Reservation{}, identity.CommandResult{}, invalidPlan()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return Reservation{}, identity.CommandResult{}, readFailure(bounded, err)
	}
	if c.pool == nil || c.pool.Raw() == nil {
		return Reservation{}, identity.CommandResult{}, coordinatorError()
	}
	var owner [16]byte
	if _, err = rand.Read(owner[:]); err != nil || owner == ([16]byte{}) {
		return Reservation{}, identity.CommandResult{}, identity.UnavailableError{}
	}
	tx, err := c.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, identity.CommandResult{}, readFailure(bounded, err)
	}
	disposition, err := lockCommandClaim(bounded, tx, q, c.keys)
	if err != nil {
		return c.failedReservation(tx, binding, identity.CommandResult{}, err)
	}
	if disposition == claimConflict {
		return c.failedReservation(tx, binding, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeConflict}, identity.ConflictError{})
	}
	journal, err := reserveJournal(bounded, tx, q, disposition, owner, c.leaseDuration)
	if err != nil {
		return c.failedReservation(tx, binding, identity.CommandResult{}, err)
	}
	admitted, err := c.freezePlan(bounded, tx, binding, q, disposition, snapshot)
	if err != nil {
		result := identity.CommandResult{}
		var conflict identity.ConflictError
		if errors.As(err, &conflict) {
			result = identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeConflict}
		}
		return c.failedReservation(tx, binding, result, err)
	}
	if journal.disposition == journalBusy || journal.disposition == journalTerminal {
		result := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: journal.retryAfter}
		if journal.result != nil {
			result = *journal.result
		}
		return c.failedReservation(tx, binding, result, nil)
	}
	// Commit owns closure after it begins. Even a driver-classified failure is
	// Unknown at this API; authoritative scoped recovery must resolve it later.
	if err = tx.Commit(bounded); err != nil {
		return Reservation{}, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown}, readFailure(bounded, err)
	}
	state := &reservationState{coordinator: c, request: q, plan: admitted, journal: journal, owner: owner}
	return Reservation{state: state}, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: c.leaseDuration}, nil
}

func (c *Coordinator) freezePlan(ctx context.Context, tx pgx.Tx, binding identity.CommandBinding, q claimRequest, d claimDisposition, p CommandPlan) (*admittedKernelPlan, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var fingerprint []byte
	if err := tx.QueryRow(ctx, `SELECT fingerprint FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&fingerprint); err != nil {
		return nil, readFailure(ctx, err)
	}
	if len(fingerprint) != 32 {
		return nil, identity.UnavailableError{}
	}
	var retained [32]byte
	copy(retained[:], fingerprint)
	encoded, err := encodeKernelPlan(binding, retained, p)
	if err != nil || len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	p.Digest, err = KernelPlanDigest(binding, retained, p)
	if err != nil {
		return nil, err
	}
	admitted, err := c.registry.admitKernelPlan(binding, retained, p)
	if err != nil {
		return nil, err
	}
	if d == claimNew {
		tag, err := tx.Exec(ctx, `UPDATE identity.commands SET command_plan=$4 WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND command_plan IS NULL`, id, string(q.tenant), q.purpose, encoded)
		if err != nil {
			return nil, readFailure(ctx, err)
		}
		if tag.RowsAffected() != 1 {
			return nil, identity.UnavailableError{}
		}
	} else {
		var stored []byte
		if err := tx.QueryRow(ctx, `SELECT command_plan FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, id, string(q.tenant), q.purpose).Scan(&stored); err != nil {
			return nil, readFailure(ctx, err)
		}
		if len(stored) == 0 {
			return nil, identity.UnavailableError{}
		}
		if !bytes.Equal(stored, encoded) {
			return nil, identity.ConflictError{}
		}
	}
	return admitted, nil
}

func (c *Coordinator) failedReservation(tx pgx.Tx, binding identity.CommandBinding, result identity.CommandResult, cause error) (Reservation, identity.CommandResult, error) {
	cleanup, stop := context.WithTimeout(context.Background(), c.maximumDuration)
	defer stop()
	if err := tx.Rollback(cleanup); err != nil {
		return Reservation{}, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown}, identity.UnavailableError{}
	}
	return Reservation{}, result, cause
}

func validCoordinatorConfig(c CoordinatorConfig) bool {
	if c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || c.LeaseDuration < time.Microsecond || c.LeaseDuration > time.Minute || c.LeaseDuration%time.Microsecond != 0 || c.CurrentFingerprintKeyVersion == 0 || len(c.RetainedFingerprintKeys) == 0 || len(c.RetainedFingerprintKeys) > 32 {
		return false
	}
	if _, ok := c.RetainedFingerprintKeys[c.CurrentFingerprintKeyVersion]; !ok {
		return false
	}
	for version, key := range c.RetainedFingerprintKeys {
		if version == 0 || key == ([32]byte{}) {
			return false
		}
	}
	return true
}

func coordinatorError() error { return identity.InvalidInputError{Field: "coordinator_configuration"} }
