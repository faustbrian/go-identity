package identity

import "slices"

// AccountUnlinkCounterContext has the existing protected account-command
// attribution contract: bounded trusted network, original primary time and
// retained digest-key versions. Reusing that contract does not grant an unlink
// permission, fresh proof or allowance. Its existing redacting diagnostics and
// serialization refusals apply unchanged. The risk owner validates actual
// attribution and current policy; this value supplies no authority.
type AccountUnlinkCounterContext = AccountLinkCounterContext

// NewAccountUnlinkCounterCommand freezes one bare unlink's exact signed intent
// and original native counter context. It performs no I/O or consumption.
// Input and returned key-version slices never alias retained state; mapping or
// restoring the command cannot renew its time or proof. Zero, foreign, mixed
// and already prepared commands fail without returning a partial command.
//
// The durable owner must bind both projections to the existing canonical
// fingerprint and enforce current/reserve/finalize/recovery phases atomically.
// Older bare accessors reject this variant so they cannot omit its counters.
// The public AccountUnlinkCommand and its one-use proof remain unchanged.
func NewAccountUnlinkCounterCommand(original Command, input AccountUnlinkCounterContext) (Command, error) {
	spec, ok := original.UnlinkAccount()
	if !ok || !input.valid() {
		return Command{}, InvalidInputError{Field: "account_unlink_counters"}
	}
	command, err := NewAccountUnlinkCommand(spec)
	if err != nil {
		return Command{}, InvalidInputError{Field: "account_unlink_counters"}
	}
	input.KeyVersions = slices.Clone(input.KeyVersions)
	command.accountCounters = &input
	return command, nil
}

// AccountUnlinkCounterCommand returns independently owned original unlink and
// counter projections only for the exact decorated variant. Bare, zero or other
// commands return false. A projection is not fresh authority; the trusted native
// owner still verifies current eligibility, proof, risk and atomic one-time use.
// Immutable commands permit concurrent readers; do not mutate inputs while
// constructing them. Returned counter slices may be changed independently.
func (c Command) AccountUnlinkCounterCommand() (AccountUnlinkCommand, AccountUnlinkCounterContext, bool) {
	if c.accountCounters == nil {
		return AccountUnlinkCommand{}, AccountUnlinkCounterContext{}, false
	}
	plain := c
	plain.accountCounters = nil
	spec, ok := plain.UnlinkAccount()
	if !ok {
		return AccountUnlinkCommand{}, AccountUnlinkCounterContext{}, false
	}
	counters := *c.accountCounters
	counters.KeyVersions = slices.Clone(counters.KeyVersions)
	return spec, counters, true
}
