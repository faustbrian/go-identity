package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"

	identity "github.com/faustbrian/go-identity"
)

// Historical decoding conserves a frozen declaration. It does not consult the
// current registry or grant permission to reserve, execute or recover a feature.
func decodeFeaturePlan(binding identity.CommandBinding, fingerprint [32]byte, encoded []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(encoded) == 0 || len(encoded) > 65536 || fingerprint == ([32]byte{}) {
		return fail()
	}
	// Supplied observation scope is also untrusted. Bound it before constructing
	// the expected CBOR map; the exact feature policy is checked after decoding.
	if len(binding.CommandID) > 22 || len(binding.TenantID) > 128 || len(binding.UserID) > 128 || len(binding.ActorID) > 128 || len(binding.ActorKind) > 128 || len(binding.OperationID) > 128 || len(binding.RecordID) > 128 || len(binding.PolicyID) > 128 || len(binding.SchemaID) > 128 || len(binding.CorrelationID) > 128 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: encoded}, ok: true}
	r.expect(5, 7)
	r.key("audits")
	count, ok := r.head(4)
	// Check the untrusted array count before allocating or narrowing it.
	if !r.ok || !ok || count == 0 || count > 64 {
		return fail()
	}
	p := CommandPlan{Audits: make([]AuditPlan, int(count))}
	for i := range p.Audits {
		a := &p.Audits[i]
		r.expect(5, 9)
		r.key("required")
		r.consume(cborBool(true))
		a.Required = true
		r.key("event_type")
		a.EventType = r.string(128)
		r.key("event_index")
		a.EventIndex = uint16(r.number(math.MaxUint16))
		r.key("binding_digest")
		r.digest(&a.BindingDigest)
		r.key("schema_version")
		a.SchemaVersion = uint32(r.number(math.MaxUint32))
		r.key("max_record_bytes")
		a.MaxRecordBytes = uint32(r.number(math.MaxUint32))
		r.key("max_aggregate_bytes")
		a.MaxAggregateBytes = uint32(r.number(math.MaxUint32))
		r.key("required_record_count")
		a.RequiredRecordCount = uint16(r.number(math.MaxUint16))
		r.key("retention_policy_version")
		a.RetentionPolicyVersion = r.number(math.MaxUint64)
	}
	r.key("binding")
	r.consume(cborMap(commandScope(binding)))
	r.key("feature")
	r.expect(5, 6)
	f := &FeatureRegistration{}
	r.key("owner")
	f.Operation.Owner = r.string(128)
	r.key("schema_id")
	f.Operation.SchemaID = r.string(128)
	r.key("contributor")
	f.Contributor = readFeaturePlanContributor(&r)
	r.key("operation_id")
	f.Operation.OperationID = r.string(128)
	r.key("schema_version")
	f.Operation.SchemaVersion = uint32(r.number(math.MaxUint32))
	r.key("record_requirement")
	f.Operation.RecordRequirement = identity.FeatureRecordRequirement(r.number(math.MaxUint8))
	p.Feature = f
	r.key("profile")
	r.consume(cborText("identity-feature-plan-v1"))
	r.key("lifecycle")
	r.expect(5, 4)
	l := &LifecyclePlan{}
	r.key("event_type")
	l.EventType = r.string(128)
	r.key("event_index")
	l.EventIndex = uint16(r.number(math.MaxUint16))
	r.key("after_version")
	l.AfterVersion = r.number(math.MaxUint64)
	r.key("before_version")
	l.BeforeVersion = r.number(math.MaxUint64)
	p.Lifecycle = l
	r.key("fingerprint")
	r.consume(cborBytes(fingerprint[:]))
	r.key("contributors")
	r.expect(4, 4)
	for range 4 {
		p.Contributors = append(p.Contributors, readFeaturePlanContributor(&r))
	}
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	canonical, err := encodeFeaturePlan(binding, fingerprint, p)
	// One encoder owns semantic bounds; byte equality also rejects nonminimal
	// lengths/integers, alternate keys/order and unsupported representations.
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fail()
	}
	p.Digest = sha256.Sum256(encoded)
	return p, nil
}

func readFeaturePlanContributor(r *planReader) ContributorDescriptor {
	r.expect(5, 3)
	r.key("owner")
	d := ContributorDescriptor{Owner: r.string(128)}
	r.key("version")
	d.Version = uint32(r.number(math.MaxUint32))
	r.key("contract_id")
	d.ContractID = r.string(256)
	return d
}
