package identity

import (
	"fmt"
	"slices"
	"time"
)

// AccountLinkCounterContext transports bounded native counter preparation for
// explicit self-user linking. Network is trusted server attribution, not a
// transport-selected identity; the risk owner must validate and canonicalize it.
// PreparedAt is the original primary UTC microsecond instant, never renewed by
// copying or restoration. KeyVersions contains 1..4 positive newest-first digest
// key aliases, matching the existing protected counter policy's rotation bound.
// These are versions, not key material. No field proves allowance, policy,
// provider identity, session possession, authorization or current freshness.
// Do not mutate inputs concurrently with construction.
type AccountLinkCounterContext struct {
	Network     string
	PreparedAt  time.Time
	KeyVersions []uint32
}

// Format redacts network and command-correlation metadata.
func (AccountLinkCounterContext) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.AccountLinkCounterContext(redacted)"))
}

// MarshalJSON rejects accidental export of private attribution.
func (AccountLinkCounterContext) MarshalJSON() ([]byte, error) {
	return nil, invalidAccountLinkCounters()
}

// MarshalText rejects accidental text or map-key export of private attribution.
func (AccountLinkCounterContext) MarshalText() ([]byte, error) {
	return nil, invalidAccountLinkCounters()
}

func invalidAccountLinkCounters() error { return InvalidInputError{Field: "account_link_counters"} }

func (c AccountLinkCounterContext) valid() bool {
	if !validDirectoryID(c.Network) || c.PreparedAt.IsZero() || c.PreparedAt.Location() != time.UTC || !validLinkExpiry(c.PreparedAt) || len(c.KeyVersions) == 0 || len(c.KeyVersions) > 4 {
		return false
	}
	for i, version := range c.KeyVersions {
		if version == 0 || i > 0 && c.KeyVersions[i-1] <= version {
			return false
		}
	}
	return true
}

// NewAccountLinkCounterCommand freezes original link intent/proof and native
// counter preparation in one opaque command. Only a bare explicit self-user
// link is supported; zero, mixed, implicit, administrative and already prepared
// variants fail with no command. Input/output slices never alias retained state.
// The exported AccountLinkCommand struct and its signed proof stay unchanged.
// No IO, clock, callback or goroutine runs; immutable copies support concurrent
// reads. This constructor supplies no authentication or transaction authority.
//
// Native executors must bind BOTH projections into the original keyed command
// fingerprint and use existing current/reserve/finalize/recovery counter owners.
// LinkAccount and Feature reject this variant so older executors cannot silently
// omit the context. AccountLinkCounterCommand is its only typed adapter accessor.
func NewAccountLinkCounterCommand(original Command, input AccountLinkCounterContext) (Command, error) {
	spec, ok := original.LinkAccount()
	if !ok || spec.Change.Mode != AccountLinkExplicit || !input.valid() {
		return Command{}, invalidAccountLinkCounters()
	}
	command, err := NewAccountLinkCommand(spec)
	if err != nil {
		return Command{}, invalidAccountLinkCounters()
	}
	input.KeyVersions = slices.Clone(input.KeyVersions)
	command.linkCounters = &input
	return command, nil
}

// AccountLinkCounterCommand returns independently owned original link and
// counter metadata only for the exact prepared variant. Zero, mixed and bare
// commands return false. Borrowing grants neither current allowance nor proof
// verification; native execution must explicitly enforce both owners. The
// original proof/session/intent/time remain unchanged and no freshness renews.
func (c Command) AccountLinkCounterCommand() (AccountLinkCommand, AccountLinkCounterContext, bool) {
	if c.linkCounters == nil {
		return AccountLinkCommand{}, AccountLinkCounterContext{}, false
	}
	plain := c
	plain.linkCounters = nil
	spec, ok := plain.LinkAccount()
	if !ok {
		return AccountLinkCommand{}, AccountLinkCounterContext{}, false
	}
	copy := *c.linkCounters
	copy.KeyVersions = slices.Clone(copy.KeyVersions)
	return spec, copy, true
}
