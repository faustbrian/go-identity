package identity_test

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestFeatureSequentialOrUnchangedRecordPolicy(t *testing.T) {
	op := featureOperation()
	if identity.FeatureVersionSequential != 0 || identity.FeatureVersionSnapshotImport != 1 || identity.FeatureVersionSequentialOrUnchanged != 2 {
		t.Fatal("version policy wire values changed")
	}
	op.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
	for _, pair := range [][2]uint64{{0, 1}, {1, 1}, {7, 7}, {7, 8}, {math.MaxUint64 - 1, math.MaxUint64}, {math.MaxUint64, math.MaxUint64}} {
		if err := op.ValidateRecordVersions(pair[0], pair[1]); err != nil {
			t.Fatalf("valid unchanged/sequential pair %v rejected: %v", pair, err)
		}
	}
	for _, pair := range [][2]uint64{{0, 0}, {0, 2}, {1, 0}, {7, 9}, {math.MaxUint64, 0}, {math.MaxUint64, 1}} {
		if op.ValidateRecordVersions(pair[0], pair[1]) == nil {
			t.Fatalf("invalid unchanged/sequential pair %v admitted", pair)
		}
	}
	op.RecordRequirement = identity.FeatureRecordOmitted
	if op.Validate() == nil || op.ValidateRecordVersions(0, 0) == nil {
		t.Fatal("record-free schema selected unchanged record semantics")
	}
}

func TestFeatureUnchangedReceiptRetainsExactPolicyAndOutcomeRules(t *testing.T) {
	r := featureResult()
	r.Feature.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
	r.Feature.BeforeVersion, r.Feature.AfterVersion = 7, 7
	if err := r.Validate(); err != nil {
		t.Fatal("committed positive unchanged receipt rejected", err)
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var restored identity.CommandResult
	if json.Unmarshal(wire, &restored) != nil || restored.Validate() != nil || restored.Feature.Operation != r.Feature.Operation || restored.Feature.BeforeVersion != 7 || restored.Feature.AfterVersion != 7 {
		t.Fatal("durable receipt lost unchanged policy or versions")
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		r.Outcome = outcome
		r.AuditEventID = ""
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Second
		} else {
			r.RetryAfter = 0
		}
		if r.Validate() != nil {
			t.Fatal("unchanged schema broke zero-version noncommit receipt", outcome)
		}
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 7, 7
		if r.Validate() == nil {
			t.Fatal("noncommit receipt claimed unchanged record effect", outcome)
		}
	}
}
