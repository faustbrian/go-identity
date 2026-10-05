package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// Historical observation validates frozen bytes, not today's registry. It
// grants neither participant ownership nor authority to resume execution.
func decodeKernelPlan(binding identity.CommandBinding, fingerprint [32]byte, encoded []byte) (CommandPlan, error) {
	if len(encoded) > 0 && encoded[0] == 0xa4 {
		return decodeIssuanceWrappedPlan(binding, fingerprint, encoded, decodeKernelPlan, encodeKernelPlan)
	}
	if len(encoded) > 0 && encoded[0] == 0xa3 {
		return decodeDeliveryWrappedPlan(binding, fingerprint, encoded, decodeKernelPlan, encodeKernelPlan)
	}
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(encoded) == 0 || len(encoded) > 65536 || fingerprint == ([32]byte{}) {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: encoded}, ok: true}
	fields, ok := r.head(5)
	if !ok || (fields != 5 && fields != 6 && fields != 7) {
		return fail()
	}
	r.key("audits")
	r.expect(4, 1)
	r.expect(5, 9)
	var audit AuditPlan
	r.key("required")
	r.consume(cborBool(true))
	audit.Required = true
	r.key("event_type")
	audit.EventType = r.string(128)
	r.key("event_index")
	audit.EventIndex = uint16(r.number(math.MaxUint16))
	r.key("binding_digest")
	r.expect(2, 32)
	if len(r.data) < 32 {
		r.ok = false
	} else {
		copy(audit.BindingDigest[:], r.data[:32])
		r.data = r.data[32:]
	}
	r.key("schema_version")
	audit.SchemaVersion = uint32(r.number(math.MaxUint32))
	r.key("max_record_bytes")
	audit.MaxRecordBytes = uint32(r.number(math.MaxUint32))
	r.key("max_aggregate_bytes")
	audit.MaxAggregateBytes = uint32(r.number(math.MaxUint32))
	r.key("required_record_count")
	audit.RequiredRecordCount = uint16(r.number(math.MaxUint16))
	r.key("retention_policy_version")
	audit.RetentionPolicyVersion = r.number(math.MaxUint64)
	r.key("binding")
	r.consume(cborMap(commandScope(binding)))
	r.key("profile")
	r.consume(cborText("identity-kernel-plan-v1"))
	plan := CommandPlan{Audits: []AuditPlan{audit}}
	if fields >= 6 {
		r.key("lifecycle")
		r.expect(5, 4)
		p := &LifecyclePlan{}
		r.key("event_type")
		p.EventType = r.string(128)
		r.key("event_index")
		p.EventIndex = uint16(r.number(math.MaxUint16))
		r.key("after_version")
		p.AfterVersion = r.number(math.MaxUint64)
		r.key("before_version")
		p.BeforeVersion = r.number(math.MaxUint64)
		plan.Lifecycle = p
	}
	if fields == 7 {
		r.key("capability")
		r.expect(5, 7)
		p := &CapabilityPlan{}
		r.key("purpose")
		p.Purpose = capability.Purpose(r.string(128))
		r.key("max_uses")
		p.MaxUses = uint32(r.number(math.MaxUint32))
		r.key("expires_at")
		p.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
		r.key("capability_id")
		p.CapabilityID = r.string(256)
		r.key("replay_digest")
		r.digest(&p.ReplayDigest)
		r.key("proof_fingerprint")
		r.digest(&p.ProofFingerprint)
		r.key("replay_key_version")
		p.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
		plan.Capability = p
	}
	r.key("fingerprint")
	r.consume(cborBytes(fingerprint[:]))
	r.key("contributors")
	count := uint64(2)
	if fields >= 6 {
		count = 3
	}
	if fields == 7 {
		count = 4
	}
	r.expect(4, count)
	// Counts are fixed by the closed profile, never by an untrusted allocation.
	for range count {
		r.expect(5, 3)
		r.key("owner")
		d := ContributorDescriptor{Owner: r.string(128)}
		r.key("version")
		d.Version = uint32(r.number(math.MaxUint32))
		r.key("contract_id")
		d.ContractID = r.string(256)
		plan.Contributors = append(plan.Contributors, d)
	}
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	canonical, err := encodeKernelPlan(binding, fingerprint, plan)
	// The encoder owns semantic policy and exact historical byte spelling.
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fail()
	}
	plan.Digest = sha256.Sum256(encoded)
	return plan, nil
}

// This fixed-depth grammar has no skip/recursive operation. Errors latch so
// truncated input cannot be interpreted as a later valid field.
type planReader struct {
	attributeReader
	ok bool
}

func (r *planReader) consume(want []byte) {
	if !r.ok || !bytes.HasPrefix(r.data, want) {
		r.ok = false
		return
	}
	r.data = r.data[len(want):]
}

func (r *planReader) key(name string) { r.consume(cborText(name)) }

func (r *planReader) expect(major byte, value uint64) {
	if !r.ok || !r.exact(major, value) {
		r.ok = false
	}
}

func (r *planReader) string(max uint64) string {
	if !r.ok {
		return ""
	}
	value, ok := r.text(max)
	r.ok = ok
	return value
}

func (r *planReader) number(max uint64) uint64 {
	if !r.ok {
		return 0
	}
	value, ok := r.head(0)
	if !ok || value > max {
		r.ok = false
		return 0
	}
	return value
}

func (r *planReader) digest(out *[32]byte) {
	r.expect(2, 32)
	if !r.ok || len(r.data) < 32 {
		r.ok = false
		return
	}
	copy(out[:], r.data[:32])
	r.data = r.data[32:]
}
