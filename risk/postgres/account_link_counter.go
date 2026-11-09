package postgres

import (
	"time"

	"github.com/faustbrian/go-authentication/v2"
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
	if !ok || spec.Change.Mode != identity.AccountLinkExplicit {
		return fail()
	}
	projection, plan, err := r.prepareAccountLinkCounterProjection(spec.Binding, spec.SessionID, subject, primaryTime)
	if err != nil {
		return fail()
	}
	mapped, err := identity.NewAccountLinkCounterCommand(command, projection)
	if err != nil {
		return fail()
	}
	return mapped, plan, nil
}

// PrepareAccountLinkPreparationCounters freezes the same protected counter
// policy around original OAuth callback/session custody, before a provider
// subject or signed link grant exists. Spec must have no counters yet; the
// returned root variant preserves the final explicit-self binding, provider
// configuration and flow. Callback aliases retain their shared bounded lifetime.
// Subject is trusted server-resolved user/session/network, and primaryTime is
// original primary UTC microsecond time. No fake account or proof is constructed.
//
// This pure operation grants no authentication, allowance or execution authority.
// The native workflow must admit current session/provider/policy authority and
// charge through the existing reservation participant before exchange. Later
// restoration uses these exact original time/key aliases without renewal.
// Zero/disabled, repeated or invalid inputs return zero and a redacted error.
// Frozen repository configuration supports concurrent calls with distinct inputs.
func (r *Repository) PrepareAccountLinkPreparationCounters(spec identity.AccountLinkPreparationCommand, callback identity.OAuthCallbackInput, bearer authentication.BearerCredential, subject risk.Subject, primaryTime time.Time) (identity.Command, kernel.CommandCounterPlan, error) {
	fail := func() (identity.Command, kernel.CommandCounterPlan, error) {
		return identity.Command{}, kernel.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	if spec.Counters.Network != "" || !spec.Counters.PreparedAt.IsZero() || len(spec.Counters.KeyVersions) != 0 {
		return fail()
	}
	projection, plan, err := r.prepareAccountLinkCounterProjection(spec.Binding, spec.SessionID, subject, primaryTime)
	if err != nil {
		return fail()
	}
	spec.Counters = projection
	command, err := identity.NewAccountLinkPreparationCommand(spec, callback, bearer)
	if err != nil {
		return fail()
	}
	return command, plan, nil
}

func (r *Repository) prepareAccountLinkCounterProjection(b identity.CommandBinding, sessionID string, subject risk.Subject, primaryTime time.Time) (identity.AccountLinkCounterContext, kernel.CommandCounterPlan, error) {
	fail := func() (identity.AccountLinkCounterContext, kernel.CommandCounterPlan, error) {
		return identity.AccountLinkCounterContext{}, kernel.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	if r == nil || r.counters == nil || subject.User != string(b.UserID) || subject.Session != sessionID || subject.Actor != "" || subject.Resource != "" || subject.Device != "" || subject.IdentifierDigest != "" {
		return fail()
	}
	scope := accountLinkCounterScope(b)
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
	plan, err := counterPlan(binding)
	if err != nil {
		return fail()
	}
	return identity.AccountLinkCounterContext{Network: subject.Network, PreparedAt: primaryTime, KeyVersions: versions}, plan, nil
}

func accountLinkCounterScope(b identity.CommandBinding) risk.Context {
	return risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
}

func (r *Repository) restoreAccountLinkCounter(command identity.Command, plan kernel.CommandCounterPlan) (restoredCounter, error) {
	spec, original, ok := command.AccountLinkCounterCommand()
	if !ok || spec.Change.Mode != identity.AccountLinkExplicit {
		return restoredCounter{}, risk.ErrInvalidCounterCommand
	}
	subject := risk.Subject{User: string(spec.Binding.UserID), Session: spec.SessionID, Network: original.Network}
	return r.restorePreparedCounter(accountLinkCounterScope(spec.Binding), subject, "", original.PreparedAt, original.KeyVersions, plan)
}

func (r *Repository) restoreAccountLinkPreparationCounter(command identity.Command, plan kernel.CommandCounterPlan) (restoredCounter, error) {
	spec, _, _, ok := command.AccountLinkPreparationInput()
	if !ok {
		return restoredCounter{}, risk.ErrInvalidCounterCommand
	}
	original := spec.Counters
	subject := risk.Subject{User: string(spec.Binding.UserID), Session: spec.SessionID, Network: original.Network}
	return r.restorePreparedCounter(accountLinkCounterScope(spec.Binding), subject, "", original.PreparedAt, original.KeyVersions, plan)
}
