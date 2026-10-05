package postgres

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func queryFingerprint() []byte { p := [32]byte{1}; return p[:] }

func queryFrozenPlan(t testing.TB, b identity.CommandBinding) []byte {
	t.Helper()
	p := CommandPlan{
		Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}},
		Audits:       []AuditPlan{{EventType: kernelCommandAudit(b.OperationID), SchemaVersion: 1, EventIndex: 7, BindingDigest: [32]byte{2}, RetentionPolicyVersion: 9, RequiredRecordCount: 1, MaxRecordBytes: 8192, MaxAggregateBytes: 16384, Required: true}},
	}
	encoded, err := encodeKernelPlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeKernelPlanConservesHistoricalBytes(t *testing.T) {
	b := codecBinding()
	encoded := queryFrozenPlan(t, b)
	p, err := decodeKernelPlan(b, [32]byte{1}, encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, lifecycle := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			candidate := p
			candidate.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
			if reverse {
				candidate.Contributors[0], candidate.Contributors[1] = candidate.Contributors[1], candidate.Contributors[0]
			}
			if lifecycle {
				candidate.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), EventIndex: 11, AfterVersion: 1}
				candidate.Contributors = append(candidate.Contributors, ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1})
			}
			wire, err := encodeKernelPlan(b, [32]byte{1}, candidate)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeKernelPlan(b, [32]byte{1}, wire)
			candidate.Digest = sha256.Sum256(wire)
			if err != nil || !reflect.DeepEqual(got, candidate) {
				t.Fatalf("historical plan lost fields: %v", err)
			}
		}
	}
}

func TestDecodeKernelPlanRejectsMalformedAndMisboundBytes(t *testing.T) {
	b := codecBinding()
	wire := queryFrozenPlan(t, b)
	cases := [][]byte{nil, {1}, append(append([]byte(nil), wire...), 0), bytes.Repeat([]byte{0}, 65537), append([]byte{0xb8, 5}, wire[1:]...), {0xbf}, {0xbb, 255, 255, 255, 255, 255, 255, 255, 255}}
	for i := range wire {
		cases = append(cases, wire[:i])
	}
	for _, input := range cases {
		p, err := decodeKernelPlan(b, [32]byte{1}, input)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || !reflect.DeepEqual(p, CommandPlan{}) {
			t.Fatal("malformed plan accepted")
		}
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CorrelationID = "foreign" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
	} {
		other := b
		mutate(&other)
		if _, err := decodeKernelPlan(other, [32]byte{1}, wire); err == nil {
			t.Fatal("foreign binding accepted")
		}
	}
	for _, fp := range [][32]byte{{}, {2}} {
		if _, err := decodeKernelPlan(b, fp, wire); err == nil {
			t.Fatal("foreign fingerprint accepted")
		}
	}
}

func TestDecodeKernelPlanRejectsInvalidFieldsAndNarrowing(t *testing.T) {
	b := codecBinding()
	wire := queryFrozenPlan(t, b)
	digest := [32]byte{2}
	for _, tc := range []struct {
		key          string
		old, invalid []byte
	}{
		{"required", cborBool(true), cborBool(false)},
		{"event_type", cborText(kernelCommandAudit(b.OperationID)), cborText("identity.user.delete")},
		{"event_index", cborUint(7), cborUint(65536)},
		{"binding_digest", cborBytes(digest[:]), nil},
		{"schema_version", cborUint(1), cborUint(1 << 32)},
		{"max_record_bytes", cborUint(8192), cborUint(0)},
		{"max_aggregate_bytes", cborUint(16384), cborUint(1)},
		{"required_record_count", cborUint(1), cborUint(65536)},
		{"retention_policy_version", cborUint(9), cborUint(0)},
		{"profile", cborText("identity-kernel-plan-v1"), cborText("other")},
		{"contributors", []byte{0x82}, []byte{0x9b, 255, 255, 255, 255, 255, 255, 255, 255}},
		{"owner", cborText("identity/postgres"), cborText("capability/postgres")},
		{"version", cborUint(1), cborUint(1 << 32)},
		{"contract_id", cborText("identity.domain"), cborText("")},
	} {
		t.Run(tc.key, func(t *testing.T) {
			old := append(cborText(tc.key), tc.old...)
			invalid := append(cborText(tc.key), tc.invalid...)
			input := bytes.Replace(wire, old, invalid, 1)
			if bytes.Equal(input, wire) {
				t.Fatal("fixture did not replace field")
			}
			p, err := decodeKernelPlan(b, [32]byte{1}, input)
			if err == nil || !reflect.DeepEqual(p, CommandPlan{}) {
				t.Fatal("invalid participant field accepted")
			}
		})
	}
}

func FuzzDecodeKernelPlan(f *testing.F) {
	b := codecBinding()
	f.Add(queryFrozenPlan(f, b))
	p, err := decodeKernelPlan(b, [32]byte{1}, queryFrozenPlan(f, b))
	if err != nil {
		f.Fatal(err)
	}
	p.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), AfterVersion: 1}
	p.CapabilityIssuance = issuanceTestPlan()
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, p.CapabilityIssuance.Contributor)
	seed, err := encodeKernelPlan(b, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{1})
	f.Add([]byte{0xbf})
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, err := decodeKernelPlan(b, [32]byte{1}, wire)
		if err != nil {
			if !reflect.DeepEqual(p, CommandPlan{}) {
				t.Fatal("partial plan escaped")
			}
			return
		}
		canonical, err := encodeKernelPlan(b, [32]byte{1}, p)
		if err != nil || !bytes.Equal(canonical, wire) || p.Digest != sha256.Sum256(wire) {
			t.Fatal("noncanonical plan accepted")
		}
	})
}

func TestCommandReceiptRejectsPlanBeforeEveryOutcome(t *testing.T) {
	b := codecBinding()
	q, _ := queryInputs(b)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, state := range []string{"pending", "committed", "aborted"} {
		o := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), fingerprint: queryFingerprint(), plan: queryFrozenPlan(t, b), state: &state, until: &now, now: now}
		if state != "pending" {
			version, class := int32(1), "denied"
			result := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeNotCommitted}
			if state == "committed" {
				class = "committed"
				result = identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", User: identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}}
			}
			var err error
			o.result, err = encodeJournalResult(claimRequest{safeFields: o.scope}, result)
			if err != nil {
				t.Fatal(err)
			}
			o.resultVersion, o.class = &version, &class
		}
		if got, _ := commandReceipt(q, o, nil); got.Binding != b {
			t.Fatal("valid historical outcome rejected")
		}
		for _, corrupt := range []func(*commandObservation){
			func(o *commandObservation) { o.plan = []byte{1} },
			func(o *commandObservation) {
				other := b
				other.CorrelationID = "foreign"
				o.plan = queryFrozenPlan(t, other)
			},
			func(o *commandObservation) { o.fingerprint = make([]byte, 32) },
		} {
			bad := o
			corrupt(&bad)
			got, err := commandReceipt(q, bad, nil)
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, identity.CommandResult{}) {
				t.Fatal("corrupt plan disclosed outcome")
			}
			foreign := q
			foreign.UserID = "foreign"
			got, err = commandReceipt(foreign, bad, nil)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || !reflect.DeepEqual(got, identity.CommandResult{}) {
				t.Fatal("wrong scope disclosed corruption")
			}
		}
	}
}
