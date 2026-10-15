package postgres

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestDecodeCommandScope(t *testing.T) {
	for _, operation := range []string{"identity.user.create", "identity.user.update-admin", "identity.profile.update", "identity.user.suspend", "identity.admin.user-ban", "identity.user.restore", "identity.admin.user-unban", "identity.account.unlink", "identity.account.link-token", "identity.identifier.attach", "identity.identifier.replace", "identity.identifier.verify", "identity.identifier.make-primary", "identity.identifier.remove"} {
		binding := codecBinding()
		binding.OperationID = operation
		binding.PolicyVersion = math.MaxUint64
		binding.SchemaVersion = math.MaxUint32
		binding.ActorKind = authorization.SubjectAPIKey
		switch operation {
		case "identity.account.unlink", "identity.identifier.attach", "identity.identifier.replace", "identity.identifier.verify", "identity.identifier.make-primary", "identity.identifier.remove":
			binding.RecordID = "record"
		case "identity.account.link-token":
			binding.RecordID = "record"
			binding.LinkMode = identity.AccountLinkAdministrative
		}
		encoded := cborMap(commandScope(binding))
		got, err := decodeCommandScope(encoded)
		if err != nil || got != binding {
			t.Fatalf("historical scope not preserved for %s", operation)
		}
		encoded[0] = 0
		if got != binding {
			t.Fatal("returned scope aliases input")
		}
	}
	for _, actor := range []authorization.SubjectKind{authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount} {
		for mode := identity.AccountLinkExplicit; mode <= identity.AccountLinkAdministrative; mode++ {
			binding := codecBinding()
			binding.ActorKind, binding.OperationID, binding.LinkMode = actor, "identity.account.link-token", mode
			binding.RecordID = strings.Repeat("é", 64)
			if got, err := decodeCommandScope(cborMap(commandScope(binding))); err != nil || got != binding {
				t.Fatal("valid record/actor variant lost")
			}
		}
	}
}

func TestDecodeCommandScopeRejectsInvalid(t *testing.T) {
	binding := codecBinding()
	good := cborMap(commandScope(binding))
	cases := [][]byte{nil, {}, {0xa0}, good[:len(good)-1], append(bytes.Clone(good), 0), make([]byte, 65537)}
	for i := range len(good) {
		cases = append(cases, good[:i])
	}
	for key := range commandScope(binding) {
		fields := commandScope(binding)
		delete(fields, key)
		cases = append(cases, cborMap(fields))
	}
	for _, mutation := range []func(map[string][]byte){
		func(m map[string][]byte) { delete(m, "actor_id") },
		func(m map[string][]byte) { m["extra"] = cborText("private") },
		func(m map[string][]byte) { m["profile"] = cborText("identity-command-v2") },
		func(m map[string][]byte) { m["command_id"] = cborBytes([]byte{1}) },
		func(m map[string][]byte) { m["command_id"] = cborText(string(binding.CommandID)) },
		func(m map[string][]byte) { m["actor_kind"] = cborText("other") },
		func(m map[string][]byte) { m["tenant_id"] = cborText("") },
		func(m map[string][]byte) { m["purpose"] = cborText("identity.unknown") },
		func(m map[string][]byte) { m["schema_version"] = cborUint(uint64(math.MaxUint32) + 1) },
		func(m map[string][]byte) { m["schema_version"] = cborUint(0) },
		func(m map[string][]byte) { m["policy_version"] = cborUint(0) },
		func(m map[string][]byte) { m["policy_version"] = []byte{0x18, 1} },
		func(m map[string][]byte) { m["record_id"] = cborText("record") },
		func(m map[string][]byte) { m["link_mode"] = cborUint(1) },
		func(m map[string][]byte) { m["link_mode"] = cborUint(256) },
		func(m map[string][]byte) { m["policy_version"] = cborInt(-1) },
		func(m map[string][]byte) { m["tenant_id"] = cborText(strings.Repeat("a", 129)) },
		func(m map[string][]byte) { m["tenant_id"] = cborText("not valid") },
		func(m map[string][]byte) { m["user_id"] = []byte{0x61, 0xff} },
		func(m map[string][]byte) { m["correlation_id"] = cborText(string(make([]byte, 4097))) },
	} {
		fields := commandScope(binding)
		mutation(fields)
		cases = append(cases, cborMap(fields))
	}
	// Correct fields in the wrong canonical order and duplicate keys must not
	// become a new representation of durable collision scope.
	fields := commandScope(binding)
	wrongOrder := []byte{0xac}
	duplicate := []byte{0xac}
	for _, key := range []string{"profile", "command_id", "tenant_id", "user_id", "actor_id", "actor_kind", "purpose", "policy_id", "policy_version", "schema_id", "schema_version", "correlation_id"} {
		wrongOrder = append(wrongOrder, cborText(key)...)
		wrongOrder = append(wrongOrder, fields[key]...)
		if key == "correlation_id" {
			key = "actor_id"
		}
		duplicate = append(duplicate, cborText(key)...)
		duplicate = append(duplicate, fields[key]...)
	}
	cases = append(cases, wrongOrder, duplicate)
	for i, encoded := range cases {
		got, err := decodeCommandScope(encoded)
		if err == nil || got != (identity.CommandBinding{}) {
			t.Fatalf("invalid scope %d returned partial authority", i)
		}
	}
}

func FuzzDecodeCommandScope(f *testing.F) {
	f.Add(cborMap(commandScope(codecBinding())))
	f.Add([]byte{0xa0})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		binding, err := decodeCommandScope(encoded)
		if err != nil {
			if binding != (identity.CommandBinding{}) {
				t.Fatal("partial scope returned on failure")
			}
			return
		}
		if !bytes.Equal(encoded, cborMap(commandScope(binding))) {
			t.Fatal("accepted noncanonical scope")
		}
		if (identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted}).Validate() != nil {
			t.Fatal("accepted invalid core binding")
		}
	})
}
