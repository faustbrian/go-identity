package risk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// RI-5: the oracle reproduces the previously committed PostgreSQL journal
// framing independently, not by calling the new production derivation.
func legacyVelocityDigest(key []byte, fields ...string) [32]byte {
	m := hmac.New(sha256.New, key)
	for _, field := range fields {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = m.Write(size[:])
		_, _ = m.Write([]byte(field))
	}
	var result [32]byte
	copy(result[:], m.Sum(nil))
	return result
}

func TestVelocityReplayIdentityPreservesJournalBytes(t *testing.T) {
	key := bytes.Repeat([]byte{0x71}, 32)
	identity, err := NewVelocityReplayIdentity("private-deployment", key)
	if err != nil {
		t.Fatal(err)
	}
	namespace := legacyVelocityDigest(key, "identity-risk-velocity-namespace-v1", "private-deployment")
	if identity.Namespace() != namespace || hex.EncodeToString(namespace[:]) != "236eb897c7a398e6e628dd15acabe7586033c0dfeb16d581593722300884a529" {
		t.Fatal("existing journal namespace changed")
	}
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("identity derivation dispatched effects")
		return CounterResult{}, nil
	}))
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	c.state.clock = func() time.Time { t.Fatal("identity derivation sampled time"); return time.Time{} }
	b := command.Bindings()
	want := legacyVelocityDigest(key, "identity-risk-velocity-attempt-v1", hex.EncodeToString(namespace[:]), b.Tenant, string(b.Operation), string(b.Phase), b.Attempt)
	got, err := identity.Attempt(command)
	if err != nil || got != want || hex.EncodeToString(got[:]) != "031abf955aee426265eb33481da9f0ca18b7379729d7de347502bc2ff7c72d7c" {
		t.Fatal("existing journal attempt changed", err)
	}
	// Neither caller key mutation nor returned array mutation changes custody.
	key[0] ^= 0xff
	copyNamespace := identity.Namespace()
	copyNamespace[0] ^= 0xff
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			repeat, err := identity.Attempt(command)
			if err != nil || repeat != want || identity.Namespace() != namespace {
				t.Error("immutable replay custody changed")
			}
		})
	}
	wg.Wait()
}

// RI-4/RI-5: replay lookup conflicts at the same attempt even when its intent
// changes; original fingerprint, policy and aliases remain separate facts.
func TestVelocityReplayIdentityScopeAndIntent(t *testing.T) {
	identity, _ := NewVelocityReplayIdentity("deployment", bytes.Repeat([]byte{1}, 32))
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { panic("unexpected effect") }))
	prepare := func(scope Context, subject Subject, phase Phase) CounterCommand {
		t.Helper()
		command, err := c.Prepare(scope, subject, phase)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	scope := testContext()
	first := prepare(scope, counterSubject(), BeforeCredential)
	want, _ := identity.Attempt(first)
	changed := counterSubject()
	changed.Network = "2001:db8::2"
	other := prepare(scope, changed, BeforeCredential)
	got, err := identity.Attempt(other)
	if err != nil || got != want || other.Bindings().Fingerprint == first.Bindings().Fingerprint {
		t.Fatal("changed intent escaped stable attempt conflict", err)
	}
	for _, modify := range []func(*Context){
		func(s *Context) { s.Tenant += "-other" },
		func(s *Context) { s.Attempt += "-other" },
		func(s *Context) { s.Operation = "identity.otp.send" },
	} {
		otherScope := scope
		modify(&otherScope)
		got, err := identity.Attempt(prepare(otherScope, counterSubject(), BeforeCredential))
		if err != nil || got == want {
			t.Fatal("cross-scope replay collision", err)
		}
	}
	otherNamespace, _ := NewVelocityReplayIdentity("other-deployment", bytes.Repeat([]byte{1}, 32))
	otherKey, _ := NewVelocityReplayIdentity("deployment", bytes.Repeat([]byte{2}, 32))
	for _, profile := range []VelocityReplayIdentity{otherNamespace, otherKey} {
		got, err := profile.Attempt(first)
		if err != nil || got == want {
			t.Fatal("cross-custody replay collision", err)
		}
	}
	// Independent preparation under a new policy/key version and later clock
	// retains lookup identity while its intent fingerprint changes.
	config := testPolicyConfig()
	config.Version++
	policy, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewCounterDigestKey(8, bytes.Repeat([]byte{2}, 32))
	rotated, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: policy, Keys: []CounterDigestKey{key}, Store: c.state.store, Clock: func() time.Time { return testContext().Now.Add(time.Minute) }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := rotated.Prepare(scope, counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	got, err = identity.Attempt(replay)
	if err != nil || got != want || replay.Bindings().Fingerprint == first.Bindings().Fingerprint || replay.Bindings().PreparedAt.Equal(first.Bindings().PreparedAt) {
		t.Fatal("rotation or time changed stable lookup", err)
	}
	// The two-dimension read lane has its own operation/phase-bound identity.
	readScope := scope
	readScope.Operation = "identity.profile.get"
	read := prepare(readScope, Subject{Network: "2001:db8::1"}, BeforeReturn)
	b := read.Bindings()
	ns := identity.Namespace()
	readWant := legacyVelocityDigest(bytes.Repeat([]byte{1}, 32), "identity-risk-velocity-attempt-v1", hex.EncodeToString(ns[:]), b.Tenant, string(b.Operation), string(b.Phase), b.Attempt)
	got, err = identity.Attempt(read)
	if err != nil || got != readWant || got == want || len(b.Targets) != 2 {
		t.Fatal("read lane lost original phase binding", err)
	}
}

// RI-4/RI-6: no arbitrary projection or protected transaction can become an
// ephemeral replay identity; all failures return a zero digest.
func TestVelocityReplayIdentityRejectsInvalidCustody(t *testing.T) {
	for _, namespace := range []string{"", "a b", "é", strings.Repeat("a", 129)} {
		if _, err := NewVelocityReplayIdentity(namespace, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid namespace admitted")
		}
	}
	for _, key := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 129)} {
		if _, err := NewVelocityReplayIdentity("deployment", key); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid key admitted")
		}
	}
	identity, _ := NewVelocityReplayIdentity(strings.Repeat("a", 128), bytes.Repeat([]byte{1}, 128))
	if identity.Namespace() == [32]byte{} || (VelocityReplayIdentity{}).Namespace() != [32]byte{} {
		t.Fatal("namespace zero semantics")
	}
	policy := testPolicy(t)
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{1}, 32))
	protected, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	command, err := protected.Prepare(Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}, Subject{User: "user", Session: "session", Network: "2001:db8::1"}, testContext().Now.UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []CounterCommand{{}, command, {state: &counterCommand{binding: CounterBinding{Tenant: "tenant", Attempt: "attempt"}}}} {
		if got, err := identity.Attempt(invalid); !errors.Is(err, ErrInvalidCounterCommand) || got != [32]byte{} {
			t.Fatal("invalid command granted replay identity")
		}
	}
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { panic("effect") }))
	live, _ := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if got, err := (VelocityReplayIdentity{}).Attempt(live); !errors.Is(err, ErrInvalidCounterCommand) || got != [32]byte{} {
		t.Fatal("zero profile accepted")
	}
	for _, value := range []VelocityReplayIdentity{identity, {}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("serialized replay custody")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("text serialization admitted")
		}
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(verb, value) != "risk.VelocityReplayIdentity(redacted)" {
				t.Fatal("unredacted replay identity")
			}
		}
	}
}
