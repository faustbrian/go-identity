package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func unlinkCounterCommand(t *testing.T) Command {
	t.Helper()
	service, owner, request, _, _ := unlinkCommandFixture(t)
	if _, err := service.AccountUnlink(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	command, err := NewAccountUnlinkCommand(*owner.spec)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestAccountUnlinkCounterContextFreezesProofAndOriginalAttribution(t *testing.T) {
	original := unlinkCounterCommand(t)
	before, _ := original.UnlinkAccount()
	input := AccountUnlinkCounterContext{Network: "2001:db8::55", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{9, 7}}
	mapped, err := NewAccountUnlinkCounterCommand(original, input)
	if err != nil {
		t.Fatal(err)
	}
	after, got, ok := mapped.AccountUnlinkCounterCommand()
	if !ok || !reflect.DeepEqual(before, after) || before.Proof.EnvelopeDigest() != after.Proof.EnvelopeDigest() || !reflect.DeepEqual(got, input) {
		t.Fatal("unlink proof, exact intent or original counter scope changed")
	}
	if _, ok := mapped.UnlinkAccount(); ok {
		t.Fatal("older executor can silently omit protected counter context")
	}
	if _, ok := mapped.Feature(); ok {
		t.Fatal("typed unlink became a generic feature")
	}
	if _, _, ok := mapped.AccountLinkCounterCommand(); ok {
		t.Fatal("unlink counter command can execute as a link")
	}
	if _, _, ok := original.AccountUnlinkCounterCommand(); ok {
		t.Fatal("original bare command was mutated")
	}
	input.KeyVersions[0] = 100
	got.KeyVersions[0] = 200
	_, retained, _ := mapped.AccountUnlinkCounterCommand()
	if retained.KeyVersions[0] != 9 || retained.PreparedAt != input.PreparedAt {
		t.Fatal("counter metadata aliases caller state or renews its original time")
	}
	if command, err := NewAccountUnlinkCounterCommand(mapped, retained); err == nil || !reflect.DeepEqual(command, Command{}) {
		t.Fatal("a prepared unlink can replace original counter context")
	}
	if wire, err := json.Marshal(retained); err == nil || len(wire) != 0 {
		t.Fatal("private counter attribution serialized")
	}
	if wire, err := retained.MarshalText(); err == nil || len(wire) != 0 {
		t.Fatal("private counter attribution exported as text")
	}
	if text := fmt.Sprintf("%#v", retained); strings.Contains(text, input.Network) || strings.Contains(text, "db8") {
		t.Fatal("private network attribution disclosed")
	}
}

func TestAccountUnlinkCounterContextRejectsInvalidAndWrongVariants(t *testing.T) {
	original := unlinkCounterCommand(t)
	base := AccountUnlinkCounterContext{Network: "192.0.2.55", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{9, 7}}
	for _, change := range []func(*AccountUnlinkCounterContext){
		func(c *AccountUnlinkCounterContext) { c.Network = "" },
		func(c *AccountUnlinkCounterContext) { c.Network = "192.0.2.55\n" },
		func(c *AccountUnlinkCounterContext) { c.Network = strings.Repeat("n", 129) },
		func(c *AccountUnlinkCounterContext) { c.Network = string([]byte{0xff}) },
		func(c *AccountUnlinkCounterContext) { c.PreparedAt = time.Time{} },
		func(c *AccountUnlinkCounterContext) { c.PreparedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(c *AccountUnlinkCounterContext) { c.PreparedAt = c.PreparedAt.Add(time.Nanosecond) },
		func(c *AccountUnlinkCounterContext) { c.PreparedAt = c.PreparedAt.In(time.FixedZone("other", 3600)) },
		func(c *AccountUnlinkCounterContext) { c.KeyVersions = nil },
		func(c *AccountUnlinkCounterContext) { c.KeyVersions = []uint32{0} },
		func(c *AccountUnlinkCounterContext) { c.KeyVersions = []uint32{7, 9} },
		func(c *AccountUnlinkCounterContext) { c.KeyVersions = []uint32{9, 9} },
		func(c *AccountUnlinkCounterContext) { c.KeyVersions = []uint32{9, 8, 7, 6, 5} },
	} {
		input := base
		change(&input)
		if command, err := NewAccountUnlinkCounterCommand(original, input); err == nil || !reflect.DeepEqual(command, Command{}) {
			t.Fatal("invalid counter scope retained a command")
		}
	}
	for _, other := range []Command{Command{}, linkCounterCommand(t)} {
		if command, err := NewAccountUnlinkCounterCommand(other, base); err == nil || !reflect.DeepEqual(command, Command{}) {
			t.Fatal("wrong command variant accepted unlink counters")
		}
		if _, _, ok := other.AccountUnlinkCounterCommand(); ok {
			t.Fatal("bare or foreign command exposed unlink counter metadata")
		}
	}
}
