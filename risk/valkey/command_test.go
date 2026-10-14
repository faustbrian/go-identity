package valkey

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

type unusedStore struct{}

func (unusedStore) Mutate(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
	panic("preparation must not dispatch a store")
}

func commandFixture(t *testing.T, versions ...uint32) (risk.Policy, []risk.CounterDigestKey, risk.CounterCoordinator) {
	t.Helper()
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]risk.CounterDigestKey, len(versions))
	for i, version := range versions {
		keys[i], err = risk.NewCounterDigestKey(version, bytes.Repeat([]byte{byte(version)}, 32))
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: unusedStore{}, Clock: func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return p, keys, c
}

func prepareFixture(t *testing.T, c risk.CounterCoordinator, tenant, attempt, network string) risk.CounterCommand {
	t.Helper()
	command, err := c.Prepare(risk.Context{Tenant: tenant, Operation: "identity.otp.send", Attempt: attempt}, risk.Subject{Network: network, Device: "private-device", IdentifierDigest: strings.Repeat("a", 64)}, risk.BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestCommandPlanAtomicScopeAndPrivateKeys(t *testing.T) {
	p, keys, c := commandFixture(t, 9, 8, 7, 6)
	layout, err := newCommandLayout("private-deployment", bytes.Repeat([]byte{0x71}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, c, "private-tenant", "private-attempt", "2001:db8::1")
	plan, err := layout.prepare(command, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.keys) != 26 || len(plan.targets) != 4 {
		t.Fatal("incomplete atomic key set")
	}
	seen := map[string]bool{}
	for _, key := range plan.keys {
		start, end := strings.IndexByte(key, '{'), strings.IndexByte(key, '}')
		if start < 0 || end <= start || key[start+1:end] != plan.slot || seen[key] {
			t.Fatal("mixed slots or duplicate keys")
		}
		seen[key] = true
		for _, raw := range []string{"private-deployment", "private-tenant", "private-attempt", "private-device", "2001:db8::1"} {
			if strings.Contains(key, raw) {
				t.Fatal("raw scope in physical key")
			}
		}
	}
	repeat, err := layout.prepare(prepareFixture(t, c, "private-tenant", "private-attempt", "2001:0db8:0:0:0:0:0:1"), [16]byte{1})
	if err != nil || !reflect.DeepEqual(plan, repeat) {
		t.Fatal("canonical replay changed plan", err)
	}
	changed, err := layout.prepare(prepareFixture(t, c, "private-tenant", "private-attempt", "2001:db8::2"), [16]byte{1})
	if err != nil || changed.keys[1] != plan.keys[1] || changed.fingerprint == plan.fingerprint {
		t.Fatal("changed intent cannot conflict at stable replay key", err)
	}
	other, err := layout.prepare(prepareFixture(t, c, "other-tenant", "private-attempt", "2001:db8::1"), [16]byte{1})
	if err != nil || other.slot == plan.slot || other.keys[1] == plan.keys[1] {
		t.Fatal("tenant collision", err)
	}
	rotated, err := layout.prepare(command, [16]byte{2})
	if err != nil || rotated.slot != plan.slot || rotated.keys[0] != plan.keys[0] || rotated.keys[1] == plan.keys[1] {
		t.Fatal("epoch lost stable health slot", err)
	}
}

func TestCommandPlanRejectsForeignCustodyAndZero(t *testing.T) {
	p, keys, c := commandFixture(t, 9, 8)
	layout, err := newCommandLayout("namespace", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	if _, err = layout.prepare(command, [16]byte{}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero epoch admitted")
	}
	if _, err = layout.prepare(risk.CounterCommand{}, [16]byte{1}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero command admitted")
	}
	foreignPolicy, _, foreign := commandFixture(t, 9, 8)
	_ = foreignPolicy
	if _, err = layout.prepare(prepareFixture(t, foreign, "tenant", "attempt", "192.0.2.1"), [16]byte{1}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("equivalent foreign policy admitted")
	}
	for _, invalid := range []struct {
		namespace string
		secret    []byte
		policy    risk.Policy
		keys      []risk.CounterDigestKey
	}{
		{"", bytes.Repeat([]byte{1}, 32), p, keys},
		{"namespace", make([]byte, 32), p, keys},
		{"namespace", bytes.Repeat([]byte{1}, 31), p, keys},
		{"namespace", bytes.Repeat([]byte{1}, 32), risk.Policy{}, keys},
		{"namespace", bytes.Repeat([]byte{1}, 32), p, nil},
		{"namespace", bytes.Repeat([]byte{1}, 32), p, []risk.CounterDigestKey{keys[1], keys[0]}},
	} {
		if _, err = newCommandLayout(invalid.namespace, invalid.secret, invalid.policy, invalid.keys); !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("invalid layout admitted")
		}
	}
	var zero commandLayout
	if _, err = zero.prepare(command, [16]byte{1}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero layout admitted")
	}
}

func TestCommandLayoutOwnsInputsAndRedacts(t *testing.T) {
	p, keys, c := commandFixture(t, 9, 8)
	secret := bytes.Repeat([]byte{1}, 32)
	layout, err := newCommandLayout("private-deployment", secret, p, keys)
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, c, "private-tenant", "attempt", "192.0.2.1")
	before, err := layout.prepare(command, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	keys[0] = keys[1]
	after, err := layout.prepare(command, [16]byte{1})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("caller mutation replaced custody", err)
	}
	for _, value := range []any{layout, before} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(verb, value); !strings.Contains(got, "redacted") || strings.Contains(got, "private-") {
				t.Fatal("format leaked scope")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("serialization exposed plan")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("text exposed plan")
		}
	}
}

func TestCounterKeyRejectsAlternateEncoding(t *testing.T) {
	valid := risk.CounterKey{Version: 9, Encoded: "rv1:9:" + strings.Repeat("A", 43)}
	if !validCounterKey(valid) {
		t.Fatal("canonical digest rejected")
	}
	for _, key := range []risk.CounterKey{
		{}, {Version: 8, Encoded: valid.Encoded}, {Version: 9, Encoded: valid.Encoded + "="},
		{Version: 9, Encoded: "rv1:9:" + strings.Repeat("A", 42) + "B"},
		{Version: 9, Encoded: "rv1:09:" + strings.Repeat("A", 43)},
		{Version: 9, Encoded: strings.Repeat("x", 65)},
	} {
		if validCounterKey(key) {
			t.Fatal("alternate or invalid digest admitted")
		}
	}
}

// Shared lookup must be reconstructible from authenticated journal digests;
// aliases and time can change intent but cannot move the replay conflict.
func TestCommandReplayUsesSharedIdentityAcrossRotationAndTime(t *testing.T) {
	secret := bytes.Repeat([]byte{0x71}, 32)
	identity, err := risk.NewVelocityReplayIdentity("private-deployment", secret)
	if err != nil {
		t.Fatal(err)
	}
	var original commandPlan
	for i, versions := range [][]uint32{{8}, {9, 8}} {
		p, keys, c := commandFixture(t, versions...)
		if i != 0 {
			c, err = risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: unusedStore{}, Clock: func() time.Time { return time.Date(2026, 10, 7, 12, 1, 0, 0, time.UTC) }, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
		}
		layout, err := newCommandLayout("private-deployment", secret, p, keys)
		if err != nil {
			t.Fatal(err)
		}
		command := prepareFixture(t, c, "private-tenant", "private-attempt", "2001:db8::1")
		plan, err := layout.prepare(command, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := identity.Attempt(command)
		expected := replayIdentityOracle(secret, "private-deployment", command.Bindings())
		if err != nil || hex.EncodeToString(digest[:]) != expected || !strings.HasSuffix(plan.keys[1], ":replay:"+expected) {
			t.Fatal("native replay cannot use authenticated journal attempt digest", err)
		}
		if !strings.HasPrefix(plan.keys[0], "irv2:{") {
			t.Fatal("shared replay reused incompatible private layout")
		}
		if i == 0 {
			original = plan
		} else if original.keys[1] != plan.keys[1] || original.slot != plan.slot || original.fingerprint == plan.fingerprint {
			t.Fatal("rotation or later preparation escaped original intent conflict")
		}
	}
}

// Independent preserved PostgreSQL byte framing, not the native helper.
func replayIdentityOracle(key []byte, namespace string, b risk.CounterBinding) string {
	mac := func(fields ...string) string {
		h := hmac.New(sha256.New, key)
		for _, field := range fields {
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(field)))
			_, _ = h.Write(length[:])
			_, _ = h.Write([]byte(field))
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	ns := mac("identity-risk-velocity-namespace-v1", namespace)
	return mac("identity-risk-velocity-attempt-v1", ns, b.Tenant, string(b.Operation), string(b.Phase), b.Attempt)
}

func TestCommandSharedIdentityReadLane(t *testing.T) {
	p, keys, c := commandFixture(t, 9, 8, 7, 6)
	secret := bytes.Repeat([]byte{0x71}, 32)
	layout, err := newCommandLayout("private-deployment", secret, p, keys)
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(risk.Context{Tenant: "private-tenant", Operation: "identity.profile.get", Attempt: "private-attempt"}, risk.Subject{Network: "2001:db8::1"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := layout.prepare(command, [16]byte{1})
	if err != nil || len(plan.targets) != 2 || len(plan.keys) != 18 || !strings.HasSuffix(plan.keys[1], ":replay:"+replayIdentityOracle(secret, "private-deployment", command.Bindings())) {
		t.Fatal("read lane lost shared bounded replay identity", err)
	}
}

func TestCommandRejectsLegacyPhysicalLayout(t *testing.T) {
	plan := scriptPlan(t, "layout-version", 9)
	for i := range plan.keys {
		plan.keys[i] = strings.Replace(plan.keys[i], "irv2:", "irv1:", 1)
	}
	if _, err := mutationArguments(plan); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("old incompatible layout admitted")
	}
}
