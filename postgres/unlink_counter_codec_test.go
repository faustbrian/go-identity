package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestAccountUnlinkCounterCommandCodecBindsOriginalProofAndCounterScope(t *testing.T) {
	original := recordUnlink(t, nil, nil)
	bare := encodedRecord(t, original)
	input := identity.AccountUnlinkCounterContext{Network: "2001:db8::55", PreparedAt: time.Unix(1000, 123000).UTC(), KeyVersions: []uint32{9, 7}}
	mapCommand := func(counters identity.AccountUnlinkCounterContext) identity.Command {
		t.Helper()
		command, err := identity.NewAccountUnlinkCounterCommand(original, counters)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := mapCommand(input)
	got, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal("native codec rejects the counter-bound canonical unlink", err)
	}
	if bytes.Equal(got.canonical, bare.canonical) || !bytes.Equal(got.safeFields, bare.safeFields) || got.commandID != bare.commandID || got.purpose != bare.purpose {
		t.Fatal("counter context changed command identity or was omitted from original intent")
	}
	if bytes.Contains(got.canonical, []byte(input.Network)) || bytes.Contains(got.safeFields, []byte(input.Network)) {
		t.Fatal("raw trusted network disclosed in stored command projection")
	}
	for _, change := range []func(*identity.AccountUnlinkCounterContext){
		func(c *identity.AccountUnlinkCounterContext) { c.Network = "192.0.2.55" },
		func(c *identity.AccountUnlinkCounterContext) { c.PreparedAt = c.PreparedAt.Add(time.Microsecond) },
		func(c *identity.AccountUnlinkCounterContext) { c.KeyVersions = []uint32{9} },
		func(c *identity.AccountUnlinkCounterContext) { c.KeyVersions = []uint32{10, 9, 7} },
	} {
		changed := input
		change(&changed)
		other, err := prepareClaim(mapCommand(changed), [32]byte{1})
		if err != nil || bytes.Equal(other.canonical, got.canonical) {
			t.Fatal("changed counter scope did not change the original fingerprint", err)
		}
	}
	otherKey, err := prepareClaim(command, [32]byte{2})
	if err != nil || bytes.Equal(otherKey.canonical, got.canonical) {
		t.Fatal("private counter attribution is not bound to retained secret key", err)
	}
	if _, ok := command.UnlinkAccount(); ok {
		t.Fatal("codec selection widened the legacy bare unlink accessor")
	}
	if again := encodedRecord(t, original); !bytes.Equal(again.canonical, bare.canonical) {
		t.Fatal("historical bare unlink encoding changed")
	}
	if capabilityReservationCommand(command, CommandPlan{}) {
		t.Fatal("fingerprinting alone enabled incomplete native unlink execution")
	}
}
