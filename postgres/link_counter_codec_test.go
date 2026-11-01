package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestAccountLinkCounterCommandCodecBindsAllOriginalContext(t *testing.T) {
	original := recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key")
	bare := encodedRecord(t, original)
	input := identity.AccountLinkCounterContext{Network: "2001:db8::12", PreparedAt: time.Unix(1000, 123000).UTC(), KeyVersions: []uint32{9, 7}}
	mapCommand := func(input identity.AccountLinkCounterContext) identity.Command {
		t.Helper()
		command, err := identity.NewAccountLinkCounterCommand(original, input)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := mapCommand(input)
	got, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal("native codec rejects canonical protected link", err)
	}
	if bytes.Equal(got.canonical, bare.canonical) || !bytes.Equal(got.safeFields, bare.safeFields) || got.purpose != bare.purpose || got.commandID != bare.commandID {
		t.Fatal("counter context changed command identity or was omitted from keyed intent")
	}
	if bytes.Contains(got.canonical, []byte(input.Network)) || bytes.Contains(got.safeFields, []byte(input.Network)) {
		t.Fatal("raw trusted network leaked into canonical or safe storage")
	}
	for _, change := range []func(*identity.AccountLinkCounterContext){
		func(c *identity.AccountLinkCounterContext) { c.Network = "192.0.2.10" },
		func(c *identity.AccountLinkCounterContext) { c.PreparedAt = c.PreparedAt.Add(time.Microsecond) },
		func(c *identity.AccountLinkCounterContext) { c.KeyVersions = []uint32{9} },
		func(c *identity.AccountLinkCounterContext) { c.KeyVersions = []uint32{10, 9, 7} },
	} {
		selected := input
		change(&selected)
		other, err := prepareClaim(mapCommand(selected), [32]byte{1})
		if err != nil || bytes.Equal(other.canonical, got.canonical) {
			t.Fatal("changed counter input omitted from original fingerprint", err)
		}
	}
	otherKey, err := prepareClaim(command, [32]byte{2})
	if err != nil || bytes.Equal(otherKey.canonical, got.canonical) {
		t.Fatal("counter attribution not bound to retained secret key", err)
	}
	if _, ok := command.LinkAccount(); ok {
		t.Fatal("native codec adoption widened the legacy command accessor")
	}
	if again := encodedRecord(t, original); !bytes.Equal(again.canonical, bare.canonical) {
		t.Fatal("bare link history changed")
	}
	// Codec support is not a declaration of complete proof/session/risk phases.
	if capabilityReservationCommand(command, CommandPlan{}) {
		t.Fatal("fingerprinting enabled unsupported reservation")
	}
}
