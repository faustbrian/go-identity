package postgres

import (
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareAccountUnlinkPreparationCounters binds the original explicit
// self-unlink intent to the trusted user, session, network and primary time.
// The input must not already contain counters. This operation performs no I/O
// and grants no password, session, counter allowance or mutation authority.
// The native owner must charge and enforce the same plan in the shared
// transaction. Invalid or unconfigured inputs return no command or plan.
// Concurrent calls use the repository's immutable policy.
func (r *Repository) PrepareAccountUnlinkPreparationCounters(spec identity.AccountUnlinkPreparationCommand, bearer authentication.BearerCredential, subject risk.Subject, primaryTime time.Time) (identity.Command, kernel.CommandCounterPlan, error) {
	fail := func() (identity.Command, kernel.CommandCounterPlan, error) {
		return identity.Command{}, kernel.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	if spec.Counters.Network != "" || !spec.Counters.PreparedAt.IsZero() || len(spec.Counters.KeyVersions) != 0 {
		return fail()
	}
	projection, plan, err := r.prepareProtectedAccountCounters(spec.Binding, spec.SessionID, subject, primaryTime)
	if err != nil {
		return fail()
	}
	spec.Counters = projection
	command, err := identity.NewAccountUnlinkPreparationCommand(spec, bearer)
	if err != nil {
		return fail()
	}
	return command, plan, nil
}

// PrepareAccountUnlinkPreparationCountersWithRetainedKeys reconstructs the
// same unlink counter plan using the original authoritative time and retained
// aliases from the original durable charge, never from request parameters.
// This does not renew freshness or make historical aliases eligible for a new
// charge. The current repository must remain the enlisted counter owner.
// It performs no I/O and denies absent or unordered retained keys.
func (r *Repository) PrepareAccountUnlinkPreparationCountersWithRetainedKeys(spec identity.AccountUnlinkPreparationCommand, bearer authentication.BearerCredential, subject risk.Subject, at time.Time, versions []uint32) (identity.Command, kernel.CommandCounterPlan, error) {
	retained, err := r.withRetainedCounterKeys(versions)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	return retained.PrepareAccountUnlinkPreparationCounters(spec, bearer, subject, at)
}

func (r *Repository) restoreAccountUnlinkCounter(b identity.CommandBinding, sessionID string, original identity.AccountUnlinkCounterContext, plan kernel.CommandCounterPlan) (restoredCounter, error) {
	subject := risk.Subject{User: string(b.UserID), Session: sessionID, Network: original.Network}
	return r.restorePreparedCounter(protectedAccountCounterScope(b), subject, "", original.PreparedAt, original.KeyVersions, plan)
}
