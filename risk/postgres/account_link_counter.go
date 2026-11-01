package postgres

import (
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareAccountLinkCommandCounters prepares the existing protected counter
// policy for a canonical explicit self-user link without converting it into a
// generic feature command. Trusted server-resolved subject User and Session must
// equal the original command; only Network may supply another dimension. All
// other subject fields must be empty. Network validation/key derivation belongs
// to the existing risk policy. PrimaryTime is original primary UTC microsecond
// time, not a new lifetime or caller-selected observation.
//
// This pure operation performs no IO, callbacks, authentication or reservation.
// Its opaque result retains the exact signed grant and original command scope;
// native fingerprinting, provider/policy/session checks, current allowance,
// atomic charge/effects and recovery remain mandatory. Zero/disabled/wrong-mode,
// repeated preparation and mismatched dimensions return redacted errors and no
// command/plan. Immutable repository configuration supports concurrent calls.
func (r *Repository) PrepareAccountLinkCommandCounters(command identity.Command, subject risk.Subject, primaryTime time.Time) (identity.Command, kernel.CommandCounterPlan, error) {
	fail := func() (identity.Command, kernel.CommandCounterPlan, error) {
		return identity.Command{}, kernel.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	spec, ok := command.LinkAccount()
	if r == nil || r.counters == nil || !ok || spec.Change.Mode != identity.AccountLinkExplicit || subject.User != string(spec.Binding.UserID) || subject.Session != spec.SessionID || subject.Actor != "" || subject.Resource != "" || subject.Device != "" || subject.IdentifierDigest != "" {
		return fail()
	}
	scope := accountLinkCounterScope(spec)
	native, err := r.counterPolicy.Prepare(scope, subject, primaryTime)
	if err != nil {
		return fail()
	}
	binding := native.Bindings()
	if binding.PolicyVersion != r.policy || len(binding.Targets) == 0 {
		return fail()
	}
	versions := make([]uint32, len(binding.Targets[0].Keys))
	for index, key := range binding.Targets[0].Keys {
		versions[index] = key.Version
	}
	mapped, err := identity.NewAccountLinkCounterCommand(command, identity.AccountLinkCounterContext{Network: subject.Network, PreparedAt: primaryTime, KeyVersions: versions})
	if err != nil {
		return fail()
	}
	plan, err := counterPlan(binding)
	if err != nil {
		return fail()
	}
	return mapped, plan, nil
}

func accountLinkCounterScope(spec identity.AccountLinkCommand) risk.Context {
	return risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}
}

func (r *Repository) restoreAccountLinkCounter(command identity.Command, plan kernel.CommandCounterPlan) (restoredCounter, error) {
	spec, original, ok := command.AccountLinkCounterCommand()
	if !ok || spec.Change.Mode != identity.AccountLinkExplicit {
		return restoredCounter{}, risk.ErrInvalidCounterCommand
	}
	subject := risk.Subject{User: string(spec.Binding.UserID), Session: spec.SessionID, Network: original.Network}
	return r.restorePreparedCounter(accountLinkCounterScope(spec), subject, "", original.PreparedAt, original.KeyVersions, plan)
}
