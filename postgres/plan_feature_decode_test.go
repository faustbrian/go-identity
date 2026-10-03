package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestDecodeFeaturePlanPreservesFrozenDeclaration(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	second := plan.Audits[0]
	second.EventIndex++
	second.EventType = "session.authority"
	plan.Audits = append(plan.Audits, second)
	plan.Lifecycle.BeforeVersion = ^uint64(0) - 1
	plan.Lifecycle.AfterVersion = ^uint64(0)
	for _, reverse := range []bool{false, true} {
		if reverse {
			plan.Contributors[0], plan.Contributors[3] = plan.Contributors[3], plan.Contributors[0]
		}
		wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
		plan.Digest = sha256.Sum256(wire)
		if err != nil || !reflect.DeepEqual(got, plan) {
			t.Fatalf("frozen declaration changed: %v", err)
		}
		if _, err := decodeKernelPlan(spec.Binding, [32]byte{1}, wire); err == nil {
			t.Fatal("feature admitted as kernel")
		}
	}
}

func TestDecodeFeaturePlanRejectsMalformedAndMisbound(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{nil, {0xbf}, bytes.Repeat([]byte{0}, 65537), append(bytes.Clone(wire), 0), append([]byte{0xb8, 7}, wire[1:]...)}
	for i := range wire {
		cases = append(cases, wire[:i])
	}
	// Independent literal malformed declarations, not another encoder round trip.
	for _, tc := range []struct {
		key      string
		old, bad []byte
	}{
		{"audits", []byte{0x81}, []byte{0x9b, 255, 255, 255, 255, 255, 255, 255, 255}},
		{"audits", []byte{0x81}, []byte{0x98, 65}},
		{"audits", []byte{0x81}, []byte{0x80}},
		{"contributors", []byte{0x84}, []byte{0x83}},
		{"required", cborBool(true), cborBool(false)},
		{"event_index", cborUint(uint64(plan.Audits[0].EventIndex)), cborUint(65536)},
		{"schema_version", cborUint(1), cborUint(1 << 32)},
		{"record_requirement", cborUint(uint64(spec.Operation.RecordRequirement)), cborUint(256)},
		{"profile", cborText("identity-feature-plan-v1"), cborText("identity-kernel-plan-v1")},
		{"after_version", cborUint(1), cborUint(2)},
		{"event_type", cborText("session.issue"), []byte{0x61, 0xff}},
		{"event_type", cborText("session.issue"), append([]byte{0x78, 0x0d}, []byte("session.issue")...)},
		{"owner", cborText("identity/session"), cborText("identity/password")},
		{"retention_policy_version", cborUint(1), cborUint(0)},
		{"max_record_bytes", cborUint(16384), cborUint(16385)},
		{"max_aggregate_bytes", cborUint(16384), cborUint(1)},
		{"required_record_count", cborUint(1), cborUint(0)},
		{"required_record_count", cborUint(1), cborUint(2)},
		{"required_record_count", cborUint(1), cborUint(65536)},
		{"before_version", cborUint(0), cborUint(^uint64(0))},
		{"binding_digest", cborBytes(plan.Audits[0].BindingDigest[:]), cborBytes(make([]byte, 32))},
		{"contract_id", cborText("identity.session"), cborText("identity.domain")},
	} {
		old := append(cborText(tc.key), tc.old...)
		bad := append(cborText(tc.key), tc.bad...)
		changed := bytes.Replace(wire, old, bad, 1)
		if bytes.Equal(changed, wire) {
			t.Fatal("mutation not exercised", tc.key)
		}
		cases = append(cases, changed)
	}
	// Replace a known key with an unknown or repeated earlier key.
	for _, key := range []string{"unknown", "audits"} {
		cases = append(cases, bytes.Replace(wire, cborText("binding"), cborText(key), 1))
	}
	wrap := bytes.Replace(wire, append(cborText("before_version"), cborUint(0)...), append(cborText("before_version"), cborUint(^uint64(0))...), 1)
	wrap = bytes.Replace(wrap, append(cborText("after_version"), cborUint(1)...), append(cborText("after_version"), cborUint(0)...), 1)
	cases = append(cases, wrap, bytes.Replace(wire, cborText("audit.records"), cborText("identity.domain"), 1))
	start := 1 + len(cborText("audits")) + 1
	end := bytes.Index(wire, cborText("binding"))
	if end <= start {
		t.Fatal("audit fixture boundary")
	}
	for _, firstIndex := range []uint64{0, 1} {
		duplicate := append(bytes.Clone(wire[:start]), wire[start:end]...)
		duplicate = append(duplicate, wire[start:end]...)
		duplicate = append(duplicate, wire[end:]...)
		duplicate[start-1] = 0x82
		duplicate = bytes.Replace(duplicate, append(cborText("event_index"), 0), append(cborText("event_index"), cborUint(firstIndex)...), 1)
		cases = append(cases, duplicate)
	}
	for _, input := range cases {
		got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, input)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("malformed prefix escaped")
		}
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CommandID = "AAAAAAAAAAAAAAAAAAAAAQ" },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorKind = "foreign" },
		func(b *identity.CommandBinding) { b.OperationID = "foreign.operation" },
		func(b *identity.CommandBinding) { b.RecordID = "foreign" },
		func(b *identity.CommandBinding) { b.PolicyID = "foreign" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.SchemaID = "foreign" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.CorrelationID = "foreign" },
		func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		foreign := spec.Binding
		mutate(&foreign)
		got, err := decodeFeaturePlan(foreign, [32]byte{1}, wire)
		if err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("foreign binding")
		}
	}
	for _, fp := range [][32]byte{{}, {2}} {
		if _, err := decodeFeaturePlan(spec.Binding, fp, wire); err == nil {
			t.Fatal("foreign fingerprint")
		}
	}
	if _, err := decodeFeaturePlan(codecBinding(), [32]byte{1}, queryFrozenPlan(t, codecBinding())); err == nil {
		t.Fatal("kernel admitted as feature")
	}
}

func TestDecodedFeaturePlanCannotReserveOrGrantExecution(t *testing.T) {
	c, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	plan.Contributors[0].Version = 7 // Historical descriptor is not today's registry.
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || got.Contributors[0].Version != 7 {
		t.Fatal("history rewritten from registry", err)
	}
	// The denial fixture must otherwise match today's complete preparation,
	// rather than being rejected merely for a foreign registry or fingerprint.
	plan.Contributors[0].Version = 1
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	currentWire, err := encodeFeaturePlan(spec.Binding, fp, prepared)
	if err != nil {
		t.Fatal(err)
	}
	current, err := decodeFeaturePlan(spec.Binding, fp, currentWire)
	if err != nil || current.Digest != prepared.Digest {
		t.Fatal("prepared fixture changed", err)
	}
	for _, coordinator := range []*Coordinator{c, nil} {
		reservation, result, err := coordinator.ReserveCommand(context.Background(), spec.Binding, command, current)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || invalid.Field != "command_plan" || reservation.state != nil || result != (identity.CommandResult{}) {
			t.Fatal("decoded history reached preparation or SQL")
		}
	}
	clear(wire)
	if got.Feature.Operation != spec.Operation || got.Audits[0].EventType != "session.issue" {
		t.Fatal("decoded history aliases source")
	}
}

func TestDecodeFeaturePlanBoundsSuppliedScopeBeforeEncoding(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.TenantID = identity.TenantID(strings.Repeat("a", 65537))
	var got CommandPlan
	allocations := testing.AllocsPerRun(5, func() { got, err = decodeFeaturePlan(spec.Binding, [32]byte{1}, wire) })
	if err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
		t.Fatal("oversized supplied scope")
	}
	if allocations != 0 {
		t.Fatalf("oversized scope allocated before rejection: %v", allocations)
	}
}

// Fixed profile-v1 bytes are inspected field-by-field rather than regenerated
// by the feature encoder. This detects mutually consistent codec omissions.
func TestDecodeFeaturePlanPinnedHistory(t *testing.T) {
	const fixture = "a76661756469747381a9687265717569726564f56a6576656e745f747970656d73657373696f6e2e69737375656b6576656e745f696e646578006e62696e64696e675f6469676573745820847775955abeb726749874f2c21dd6a500b2a62c7eaf2eb4298ef9a447411a9b6e736368656d615f76657273696f6e01706d61785f7265636f72645f6279746573194000736d61785f6167677265676174655f62797465731940007572657175697265645f7265636f72645f636f756e74017818726574656e74696f6e5f706f6c6963795f76657273696f6e016762696e64696e67ad6770726f66696c65736964656e746974792d636f6d6d616e642d763167707572706f7365766964656e746974792e73657373696f6e2e697373756567757365725f6964781a303141525a334e44454b54535634525246465136394735464156686163746f725f6964676163746f722d6169706f6c6963795f696466706f6c696379697265636f72645f69646973657373696f6e2d6169736368656d615f69646d73657373696f6e2d69737375656974656e616e745f69646874656e616e742d616a6163746f725f6b696e6464757365726a636f6d6d616e645f696450000000000000000000000000000000046e636f7272656c6174696f6e5f69646b636f7272656c6174696f6e6e706f6c6963795f76657273696f6e016e736368656d615f76657273696f6e016766656174757265a6656f776e6572706964656e746974792f73657373696f6e69736368656d615f69646d73657373696f6e2d69737375656b636f6e7472696275746f72a3656f776e657278196964656e746974792f73657373696f6e2f706f7374677265736776657273696f6e016b636f6e74726163745f6964706964656e746974792e73657373696f6e6c6f7065726174696f6e5f6964766964656e746974792e73657373696f6e2e69737375656e736368656d615f76657273696f6e01727265636f72645f726571756972656d656e74026770726f66696c6578186964656e746974792d666561747572652d706c616e2d7631696c6966656379636c65a46a6576656e745f747970657273657373696f6e2e637265617465642e76316b6576656e745f696e646578006d61667465725f76657273696f6e016e6265666f72655f76657273696f6e006b66696e6765727072696e74582001000000000000000000000000000000000000000000000000000000000000006c636f6e7472696275746f727384a3656f776e6572716964656e746974792f706f7374677265736776657273696f6e016b636f6e74726163745f69646f6964656e746974792e646f6d61696ea3656f776e65726e61756469742f706f7374677265736776657273696f6e016b636f6e74726163745f69646d61756469742e7265636f726473a3656f776e65726f6f7574626f782f706f7374677265736776657273696f6e016b636f6e74726163745f6964726964656e746974792e6c6966656379636c65a3656f776e657278196964656e746974792f73657373696f6e2f706f7374677265736776657273696f6e016b636f6e74726163745f6964706964656e746974792e73657373696f6e"
	wire, err := hex.DecodeString(fixture)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFeaturePlan(featureCodecSpec().Binding, [32]byte{1}, wire)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes, err := hex.DecodeString("847775955abeb726749874f2c21dd6a500b2a62c7eaf2eb4298ef9a447411a9b")
	if err != nil {
		t.Fatal(err)
	}
	var bindingDigest [32]byte
	copy(bindingDigest[:], digestBytes)
	expected := CommandPlan{
		Feature:      &FeatureRegistration{Operation: identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, Contributor: ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session", Version: 1}},
		Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, {Owner: "identity/session/postgres", ContractID: "identity.session", Version: 1}},
		Audits:       []AuditPlan{{Required: true, EventType: "session.issue", BindingDigest: bindingDigest, SchemaVersion: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RequiredRecordCount: 1, RetentionPolicyVersion: 1}},
		Lifecycle:    &LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Digest: sha256.Sum256(wire),
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatal("pinned field conservation")
	}
}

func TestDecodeFeaturePlanRecordFreeAndBoundedAuditSet(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	spec.Binding.RecordID = ""
	spec.Operation.RecordRequirement = identity.FeatureRecordOmitted
	plan.Feature.Operation = spec.Operation
	plan.Lifecycle.BeforeVersion, plan.Lifecycle.AfterVersion = 0, 0
	first := plan.Audits[0]
	plan.Audits = nil
	for i := range 64 {
		a := first
		a.EventIndex = uint16(i)
		plan.Audits = append(plan.Audits, a)
	}
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || len(got.Audits) != 64 || got.Lifecycle.AfterVersion != 0 {
		t.Fatal("bounded record-free history", err)
	}
	got.Audits[0].EventType = "changed"
	got.Contributors[0].Owner = "changed"
	got.Feature.Operation.Owner = "changed"
	again, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || again.Audits[0].EventType != first.EventType || again.Contributors[0] != plan.Contributors[0] || again.Feature.Operation != spec.Operation {
		t.Fatal("decoded plans share mutation")
	}
}

func FuzzDecodeFeaturePlan(f *testing.F) {
	// Keep the seed independent of Coordinator and test-only phase fixtures.
	s := featureCodecSpec()
	p := CommandPlan{
		Feature:      &FeatureRegistration{Operation: s.Operation, Contributor: ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "session.domain", Version: 1}},
		Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, {Owner: "identity/session/postgres", ContractID: "session.domain", Version: 1}},
		Audits:       []AuditPlan{{Required: true, EventType: "session.issue", SchemaVersion: 1, BindingDigest: [32]byte{2}, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 8192, MaxAggregateBytes: 16384}},
		Lifecycle:    &LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1},
	}
	wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "standard"
	wire, err = encodeFeaturePlan(s.Binding, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte{0xbf})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, input)
		if err != nil {
			if !reflect.DeepEqual(got, CommandPlan{}) {
				t.Fatal("partial plan")
			}
			return
		}
		encoded, err := encodeFeaturePlan(s.Binding, [32]byte{1}, got)
		if err != nil || !bytes.Equal(encoded, input) || got.Digest != sha256.Sum256(input) {
			t.Fatal("noncanonical observation")
		}
	})
}
