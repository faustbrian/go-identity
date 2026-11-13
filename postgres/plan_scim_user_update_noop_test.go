package postgres

import (
	"bytes"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestSCIMUserUpdatePlanNoopKeepsProjectionVersion(t *testing.T) {
	b, p := scimUpdatePlanExample()
	if p.Feature.Operation.VersionPolicy != identity.FeatureVersionSequentialOrUnchanged {
		t.Fatal("immutable PATCH descriptor cannot represent both effective and no-op input")
	}
	for _, pair := range [][2]uint64{{7, 7}, {math.MaxUint64, math.MaxUint64}, {7, 8}} {
		p.SCIMUserUpdate.Required = false
		p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = pair[0], pair[1]
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal("no-core PATCH changed/rejected native projection version", pair, err)
		}
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || decoded.Lifecycle.BeforeVersion != pair[0] || decoded.Lifecycle.AfterVersion != pair[1] || decoded.SCIMUserUpdate.Required {
			t.Fatal("durable no-op plan lost exact versions", err)
		}
		canonical, err := encodeFeaturePlan(b, [32]byte{1}, decoded)
		if err != nil || !bytes.Equal(canonical, wire) {
			t.Fatal("no-op plan encoding is noncanonical")
		}
		if pair[0] == pair[1] {
			altered := bytes.Replace(wire, append(cborText("required"), cborBool(false)...), append(cborText("required"), cborBool(true)...), 1)
			if bytes.Equal(altered, wire) {
				t.Fatal("required-marker fixture did not change")
			}
			if _, err := decodeFeaturePlan(b, [32]byte{1}, altered); err == nil {
				t.Fatal("durable required update escaped sequential lifecycle guard")
			}
		}
	}
	for _, pair := range [][2]uint64{{0, 0}, {7, 9}, {math.MaxUint64, 0}} {
		p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = pair[0], pair[1]
		if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
			t.Fatal("invalid no-core lifecycle accepted", pair)
		}
	}
	p.SCIMUserUpdate.Required = true
	p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 7, 7
	if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
		t.Fatal("required core update produced unchanged lifecycle")
	}
	p.Lifecycle.AfterVersion = 8
	if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err != nil {
		t.Fatal("required sequential core update rejected", err)
	}
	replace := scimUserUpdateOperation("identity.scim.user-replace")
	if replace.VersionPolicy != identity.FeatureVersionSequential {
		t.Fatal("replace acquired no-op record policy")
	}
}

func TestSCIMUnchangedObservedScopeConservesExactPolicy(t *testing.T) {
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	operation := scimUserUpdateOperation(intent.Binding.OperationID)
	operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
	encoded := commandSafeFields(intent.Binding, &operation)
	binding, restored, err := decodeObservedScope(encoded)
	if err != nil || binding != intent.Binding || restored == nil || *restored != operation {
		t.Fatal("historical no-op PATCH scope lost immutable version policy", err)
	}
	for _, bad := range []uint64{0, 3, 255} {
		changed := bytes.Replace(encoded, append(cborText("version_policy"), cborUint(2)...), append(cborText("version_policy"), cborUint(bad)...), 1)
		if _, _, err := decodeObservedScope(changed); err == nil {
			t.Fatal("unknown/noncanonical version policy admitted", bad)
		}
	}
}
