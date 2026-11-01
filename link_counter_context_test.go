package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

func linkCounterCommand(t *testing.T) Command {
	t.Helper()
	service, owner, request, _, _ := linkCommandFixture(t)
	if _, err := service.AccountLink(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	command, err := NewAccountLinkCommand(*owner.spec)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestAccountLinkCounterContextRetainsCanonicalProofAndCopies(t *testing.T) {
	original := linkCounterCommand(t)
	before, _ := original.LinkAccount()
	input := AccountLinkCounterContext{Network: "2001:db8::1234", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{9, 7}}
	mapped, err := NewAccountLinkCounterCommand(original, input)
	if err != nil {
		t.Fatal(err)
	}
	after, got, ok := mapped.AccountLinkCounterCommand()
	if !ok || !reflect.DeepEqual(before, after) || after.Proof.EnvelopeDigest() != before.Proof.EnvelopeDigest() {
		t.Fatal("canonical link intent or original proof changed")
	}
	if _, ok := mapped.Feature(); ok {
		t.Fatal("canonical link became a generic feature command")
	}
	if _, ok := mapped.LinkAccount(); ok {
		t.Fatal("legacy executor can silently omit protected counter context")
	}
	if _, ok := mapped.ChangeIdentifier(); ok {
		t.Fatal("counter link became an identifier command")
	}
	if _, ok := mapped.UnlinkAccount(); ok {
		t.Fatal("counter link became an unlink command")
	}
	if _, _, ok := original.AccountLinkCounterCommand(); ok {
		t.Fatal("original command was mutated")
	}
	if !ok || !reflect.DeepEqual(got, input) {
		t.Fatal("counter context lost")
	}
	input.KeyVersions[0] = 100
	got.KeyVersions[0] = 200
	_, again, _ := mapped.AccountLinkCounterCommand()
	if again.KeyVersions[0] != 9 || again.PreparedAt != input.PreparedAt {
		t.Fatal("context aliased or original time renewed")
	}
	if _, err := NewAccountLinkCounterCommand(mapped, input); err == nil {
		t.Fatal("original counter context could be replaced")
	}
	if bytes, err := json.Marshal(again); err == nil || len(bytes) != 0 {
		t.Fatal("private network context serialized")
	}
	if text := fmt.Sprintf("%#v", again); strings.Contains(text, "db8") || strings.Contains(text, "1234") {
		t.Fatal("network context leaked in formatting")
	}
	if raw, err := again.MarshalText(); err == nil || len(raw) != 0 {
		t.Fatal("private attribution exported as text")
	}
}

func TestAccountLinkCounterContextRejectsOtherAuthenticatedLinkModes(t *testing.T) {
	for _, mode := range []AccountLinkMode{AccountLinkAdministrative, AccountLinkImplicit} {
		service, owner, request, caps, _ := linkCommandFixture(t)
		if _, err := service.AccountLink(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		spec := *owner.spec
		spec.Change.Mode, spec.Binding.LinkMode = mode, mode
		if mode == AccountLinkAdministrative {
			spec.Change.Reason = "approved-recovery"
		} else {
			spec.Binding.ActorKind, spec.Binding.ActorID = authorization.SubjectServiceAccount, "provider-workload"
			spec.SessionID, spec.SessionVersion = "", 0
			spec.PreAuthTransactionID = "AAAAAAAAAAAAAAAAAAAABg"
			spec.Change.MatchedIdentifier, spec.Change.VerifiedCanonicalIdentifier = "identifier-a", "synthetic@example.test"
			spec.Change.ExpectedIdentifierAuthorityVersion, spec.Change.ExpectedIdentifierVersion, spec.Change.ExpectedVerificationVersion = 1, 1, 1
		}
		payload := spec.Proof.Payload()
		payload.Caveats = linkCaveats(spec)
		token, _, err := caps.Issue(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		spec.Proof, err = caps.Verify(context.Background(), token, "identity.account.link-token", payload.Audiences[0])
		if err != nil {
			t.Fatal(err)
		}
		command, err := NewAccountLinkCommand(spec)
		if err != nil {
			t.Fatal("valid authenticated other-mode fixture", err)
		}
		if _, err := NewAccountLinkCounterCommand(command, AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{7}}); err == nil {
			t.Fatal("explicit-only counter context admitted another link policy")
		}
	}
}

func TestAccountLinkCounterContextRejectsInvalidAndWrongVariant(t *testing.T) {
	original := linkCounterCommand(t)
	base := AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{9, 7}}
	for _, change := range []func(*AccountLinkCounterContext){
		func(c *AccountLinkCounterContext) { c.Network = "" },
		func(c *AccountLinkCounterContext) { c.Network = "192.0.2.15\n" },
		func(c *AccountLinkCounterContext) { c.Network = strings.Repeat("n", 129) },
		func(c *AccountLinkCounterContext) { c.Network = string([]byte{0xff}) },
		func(c *AccountLinkCounterContext) { c.PreparedAt = time.Time{} },
		func(c *AccountLinkCounterContext) { c.PreparedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(c *AccountLinkCounterContext) { c.PreparedAt = c.PreparedAt.Add(time.Nanosecond) },
		func(c *AccountLinkCounterContext) { c.PreparedAt = c.PreparedAt.In(time.FixedZone("other", 3600)) },
		func(c *AccountLinkCounterContext) { c.KeyVersions = nil },
		func(c *AccountLinkCounterContext) { c.KeyVersions = []uint32{0} },
		func(c *AccountLinkCounterContext) { c.KeyVersions = []uint32{7, 9} },
		func(c *AccountLinkCounterContext) { c.KeyVersions = []uint32{9, 9} },
		func(c *AccountLinkCounterContext) { c.KeyVersions = []uint32{9, 8, 7, 6, 5} },
	} {
		selected := base
		change(&selected)
		if command, err := NewAccountLinkCounterCommand(original, selected); err == nil || !reflect.DeepEqual(command, Command{}) {
			t.Fatal("invalid context retained a command")
		}
	}
	if _, err := NewAccountLinkCounterCommand(Command{}, base); err == nil {
		t.Fatal("zero command accepted")
	}
	if _, _, ok := (Command{}).AccountLinkCounterCommand(); ok {
		t.Fatal("zero command disclosed context")
	}
	spec, _ := original.LinkAccount()
	spec.Change.Mode, spec.Binding.LinkMode, spec.Change.Reason = AccountLinkAdministrative, AccountLinkAdministrative, "approved-recovery"
	// The source cannot be reconstructed by changing signed intent; this
	// constructor must never treat arbitrary public metadata as proof authority.
	if _, err := NewAccountLinkCommand(spec); err == nil {
		t.Fatal("counter setup silently forged a different link mode")
	}
}
