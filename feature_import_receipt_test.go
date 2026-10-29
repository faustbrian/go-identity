package identity_test

import (
	"encoding/json"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestFeatureSnapshotImportPreservesSourceRecordVersion(t *testing.T) {
	r := featureResult()
	r.Feature.Operation.Owner = "identity/apikey"
	r.Feature.Operation.OperationID = "identity.apikey.import"
	r.Feature.Operation.SchemaID = "apikey-import-v1"
	r.Feature.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
	r.Binding.OperationID = r.Feature.Operation.OperationID
	r.Binding.SchemaID = r.Feature.Operation.SchemaID
	for _, source := range []uint64{1, 3, math.MaxUint64} {
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, source
		if err := r.Validate(); err != nil {
			t.Fatal("snapshot import changed or rejected original source version", source, err)
		}
	}
	for _, pair := range [][2]uint64{{0, 0}, {1, 2}, {2, 3}, {3, 4}, {math.MaxUint64, 0}} {
		r.Feature.BeforeVersion, r.Feature.AfterVersion = pair[0], pair[1]
		if r.Validate() == nil {
			t.Fatal("snapshot-import policy admitted an update or invalid initial version")
		}
	}
	r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 3
	r.Feature.Operation.VersionPolicy = identity.FeatureVersionSequential
	if r.Validate() == nil {
		t.Fatal("ordinary creation acquired imported-version semantics")
	}
	r.Feature.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
	r.Feature.Operation.RecordRequirement = identity.FeatureRecordOmitted
	r.Binding.RecordID = ""
	r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
	if r.Validate() == nil {
		t.Fatal("record-free operation selected imported record semantics")
	}
	r = featureResult()
	r.Feature.Operation.VersionPolicy = identity.FeatureVersionPolicy(255)
	if r.Validate() == nil {
		t.Fatal("unknown version policy accepted")
	}
}

func TestFeatureDefaultVersionPolicyPreservesCanonicalDeclaration(t *testing.T) {
	op := featureOperation()
	wire, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	const before = `{"Owner":"identity/session","OperationID":"identity.session.issue","SchemaID":"session-issue","SchemaVersion":1,"RecordRequirement":2}`
	if string(wire) != before {
		t.Fatal("existing feature declaration bytes changed")
	}
	if op.ValidateRecordVersions(0, 1) != nil || op.ValidateRecordVersions(math.MaxUint64-1, math.MaxUint64) != nil || op.ValidateRecordVersions(0, 3) == nil || op.ValidateRecordVersions(math.MaxUint64, 0) == nil {
		t.Fatal("existing sequential transition changed")
	}
}
