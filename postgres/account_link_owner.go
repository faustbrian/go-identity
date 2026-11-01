package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// AccountLinkUnitOfWorkConfig selects the positive audit retention-policy
// revision. Zero is invalid; configuration is copied and immutable after setup.
type AccountLinkUnitOfWorkConfig struct{ RetentionPolicyVersion uint64 }

// AccountLinkUnitOfWork is the sealed explicit-self-link implementation of the
// root durable seam. Use behind AccountLinkService with the actual configured
// native OAuth participant; it is not a provider-verification or HTTP endpoint.
// It owns no pool, goroutine, second ledger or transaction engine. Concurrent
// service calls use independent bounded Work; each Work remains serial-use.
type AccountLinkUnitOfWork struct {
	coordinator  *Coordinator
	repository   *Repository
	provider     AccountLinkContributor
	contributors []ContributorDescriptor
	retention    uint64
}

var _ identity.UnitOfWork = (*AccountLinkUnitOfWork)(nil)

// NewAccountLinkUnitOfWork validates complete typed native phase composition,
// not names alone. It does no I/O or callbacks. Pools remain caller-owned.
// Missing recovery/current/finalization phases fail before any reservation.
func NewAccountLinkUnitOfWork(c *Coordinator, r *Repository, config AccountLinkUnitOfWorkConfig) (*AccountLinkUnitOfWork, error) {
	if c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.registry.state == nil || r == nil || r.read == nil || config.RetentionPolicyVersion == 0 {
		return nil, coordinatorError()
	}
	o := &AccountLinkUnitOfWork{coordinator: c, repository: r, retention: config.RetentionPolicyVersion}
	wanted := []string{"identity/postgres", "audit/postgres", "outbox/postgres", "capability/postgres", "identity/risk/postgres", "identity/oauth/postgres"}
	for _, owner := range wanted {
		var selected *registeredContributor
		for i := range c.registry.state.entries {
			entry := &c.registry.state.entries[i]
			if entry.descriptor.Owner != owner {
				continue
			}
			if owner == "identity/oauth/postgres" && entry.descriptor != accountLinkOwnerDescriptor() {
				continue
			}
			if owner == "capability/postgres" && entry.descriptor != (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) {
				continue
			}
			if selected != nil {
				return nil, coordinatorError()
			}
			selected = entry
		}
		if selected == nil {
			return nil, coordinatorError()
		}
		if _, ok := selected.contributor.(RecoveryContributor); !ok {
			return nil, coordinatorError()
		}
		switch owner {
		case "identity/postgres":
			if selected.contributor != r {
				return nil, coordinatorError()
			}
		case "audit/postgres":
			if _, ok := selected.contributor.(AuditContributor); !ok {
				return nil, coordinatorError()
			}
		case "outbox/postgres":
			if _, ok := selected.contributor.(LifecycleContributor); !ok {
				return nil, coordinatorError()
			}
		case "capability/postgres":
			if _, ok := selected.contributor.(CapabilityExecutionContributor); !ok {
				return nil, coordinatorError()
			}
		case "identity/risk/postgres":
			if _, ok := selected.contributor.(CommandCounterAdmissionContributor); !ok {
				return nil, coordinatorError()
			}
		case "identity/oauth/postgres":
			p, ok := selected.contributor.(AccountLinkContributor)
			if !ok || !sameParticipant(p, p) {
				return nil, coordinatorError()
			}
			o.provider = p
		}
		o.contributors = append(o.contributors, selected.descriptor)
	}
	return o, nil
}

// Format omits runtime dependencies and retained security configuration.
func (AccountLinkUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountLinkUnitOfWork(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (AccountLinkUnitOfWork) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

// Execute completes already-authorized root link intent with the exact native
// current provider/session/risk owner. Every domain, proof, provider, audit and
// lifecycle effect commits together. Exact replay returns the original receipt;
// failures roll back and use the same coordinator's conservative recovery rules.
// Native preparation may enrich counters but cannot change the signed intent.
func (o *AccountLinkUnitOfWork) Execute(ctx context.Context, original identity.Command) (result identity.CommandResult, err error) {
	if o == nil || o.coordinator == nil || o.repository == nil || ctx == nil {
		return result, coordinatorError()
	}
	spec, ok := original.LinkAccount()
	if !ok || !accountLinkBinding(spec.Binding) {
		return result, invalidPlan()
	}
	c := o.coordinator
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	command, counters, capability, err := o.prepare(bounded, original)
	if err != nil {
		return result, err
	}
	seed, err := kernelMutationAudit(bounded, spec.Binding, spec.Change.ExpectedAccountVersion, time.Now().UTC().Truncate(time.Microsecond), "committed")
	if err != nil {
		return result, err
	}
	digest, err := AuditBindingDigest(spec.Binding, seed)
	if err != nil {
		return result, err
	}
	plan, err := c.PrepareCommandPlan(spec.Binding, command, CommandPlan{Contributors: o.contributors,
		Audits:    []AuditPlan{{EventType: kernelCommandAudit(spec.Binding.OperationID), SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: o.retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}},
		Lifecycle: &LifecyclePlan{EventType: kernelLifecycleEvent(spec.Binding.OperationID), BeforeVersion: spec.Change.ExpectedAccountVersion, AfterVersion: spec.Change.Account.Version}, Capability: &capability, CommandCounters: &counters})
	if err != nil {
		return result, err
	}
	reservation, result, err := c.ReserveCommand(bounded, spec.Binding, command, plan)
	if err != nil || reservation.state == nil {
		return coreCreationReceipt(result, err)
	}
	return o.executeReservation(bounded, reservation, command)
}

func (o *AccountLinkUnitOfWork) executeReservation(bounded context.Context, reservation Reservation, command identity.Command) (result identity.CommandResult, err error) {
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || reservation.state == nil {
		return result, invalidPreparation()
	}
	c := o.coordinator
	result = identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeUnknown}
	var work Work
	defer func() {
		panicked := recover() != nil
		if work.state != nil && !work.state.closed {
			result, err = c.Abort(work, identity.UnavailableError{})
		}
		if panicked {
			cleanup, stop := context.WithTimeout(context.Background(), c.maximumDuration)
			defer stop()
			result, err = c.recoverCommandReceipt(cleanup, creationRecoveryQuery(spec.Binding))
		}
		result, err = coreCreationReceipt(result, err)
	}()
	work, err = c.Begin(bounded, reservation)
	if err != nil {
		return result, err
	}
	now, err := work.DatabaseTime(bounded)
	if err != nil {
		return c.Abort(work, err)
	}
	work.state.execution.abortAudits = make(map[string]audit.Record, 5)
	for _, class := range []string{"denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		record, e := kernelMutationAudit(bounded, spec.Binding, spec.Change.ExpectedAccountVersion, now, class)
		if e != nil {
			return c.Abort(work, e)
		}
		work.state.execution.abortAudits[class] = record
	}
	result, err = o.repository.applyAccountLink(bounded, work, command)
	if err != nil {
		return c.Abort(work, err)
	}
	return c.Commit(work, result)
}

func (o *AccountLinkUnitOfWork) prepare(ctx context.Context, original identity.Command) (command identity.Command, counters CommandCounterPlan, capability CapabilityPlan, err error) {
	defer func() {
		if recover() != nil {
			command, counters, capability, err = identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	command, counters, capability, err = o.provider.PrepareAccountLink(ctx, original)
	if err != nil {
		return identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, identity.UnavailableError{}
	}
	spec, _, ok := command.AccountLinkCounterCommand()
	base, e := identity.NewAccountLinkCommand(spec)
	if !ok || e != nil {
		return identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, invalidPlan()
	}
	before, e := prepareClaim(original, o.coordinator.keys.retained[o.coordinator.keys.current])
	after, other := prepareClaim(base, o.coordinator.keys.retained[o.coordinator.keys.current])
	if e != nil || other != nil || !bytes.Equal(before.canonical, after.canonical) {
		return identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, invalidPlan()
	}
	return command, counters, capability, nil
}

// Recover reads the exact original scoped primary receipt without re-exchange,
// new signing, mutation replay or session issuance. Expired pending work needs
// unanimous native negative evidence; uncertainty remains pending. Current
// application authorization/redaction still belongs to AccountLinkService.
func (o *AccountLinkUnitOfWork) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if o == nil || o.coordinator == nil || ctx == nil || q.OperationID != "identity.account.link-token" || q.LinkMode != identity.AccountLinkExplicit || q.RecordID == "" || string(q.ActorID) != string(q.UserID) {
		return identity.CommandResult{}, invalidPlan()
	}
	bounded, cancel := context.WithTimeout(ctx, o.coordinator.maximumDuration)
	defer cancel()
	result, err := o.coordinator.recoverCommandReceipt(bounded, q)
	return coreCreationReceipt(result, err)
}
