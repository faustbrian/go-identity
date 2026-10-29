package postgres

import (
	"bytes"
	"math"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestFeatureSnapshotImportBindsCommandAndPreparationPolicy(t *testing.T) {
	s := featureCodecSpec()
	ordinary, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	registration := FeatureRegistration{Contributor: featureRegistryInput().descriptor, Operation: s.Operation}
	originalPreparation := requestPreparationIdentity(registration)
	s.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
	imported, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ordinary.canonical, imported.canonical) || bytes.Equal(ordinary.safeFields, imported.safeFields) {
		t.Fatal("snapshot version policy omitted from command intent or collision scope")
	}
	if !bytes.Equal(commandSafeFields(s.Binding, &s.Operation), imported.safeFields) {
		t.Fatal("reconstructed collision scope lost snapshot policy")
	}
	registration.Operation = s.Operation
	if requestPreparationIdentity(registration) == originalPreparation {
		t.Fatal("snapshot policy borrowed sequential request preparation")
	}
	fields, err := encodeFeature(s, [32]byte{1})
	if err != nil || !bytes.Equal(fields["version_policy"], []byte{1}) {
		t.Fatal("feature payload omitted exact policy", err)
	}
}

func TestFeatureSnapshotImportPreservesPlanAndReceiptSourceVersions(t *testing.T) {
	for _, source := range []uint64{1, 3, math.MaxUint64} {
		c, command, p := featurePlanFixture(t)
		s, _ := command.Feature()
		s.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
		p.Feature.Operation = s.Operation
		p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, source
		// Register the actual schema selection, rather than allowing a request
		// or recovered plan to enable a different policy in the live registry.
		c.registry.state.features[0].Operation = s.Operation
		prepared, err := c.PrepareCommandPlan(s.Binding, featureCodecCommand(t, s), p)
		if err != nil {
			t.Fatal("registered snapshot import cannot preserve source version", source, err)
		}
		claim, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		fp := claimFingerprint([32]byte{1}, claim.canonical)
		wire, err := encodeFeaturePlan(s.Binding, fp, prepared)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeFeaturePlan(s.Binding, fp, wire)
		if err != nil || !reflect.DeepEqual(decoded, prepared) {
			t.Fatal("historical import plan changed source version or policy", source, err)
		}
		receipt := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: s.Operation, AfterVersion: source}}
		encoded, err := encodeJournalResult(claim, receipt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeJournalResult(claim, encoded)
		if err != nil || got.Feature == nil || got.Feature.Operation != s.Operation || got.Feature.BeforeVersion != 0 || got.Feature.AfterVersion != source {
			t.Fatal("journal import receipt changed source version", err)
		}
		for _, pair := range [][2]uint64{{0, 0}, {1, 2}, {2, 3}, {math.MaxUint64, 0}} {
			prepared.Lifecycle.BeforeVersion, prepared.Lifecycle.AfterVersion = pair[0], pair[1]
			if _, err := FeaturePlanDigest(s.Binding, fp, prepared); err == nil {
				t.Fatal("snapshot policy admitted local update or invalid initial version")
			}
		}
	}
}

func TestFeatureSnapshotImportCannotReplaceRegisteredSequentialPolicy(t *testing.T) {
	c, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	s.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
	p.Feature.Operation = s.Operation
	if _, err := c.PrepareCommandPlan(s.Binding, featureCodecCommand(t, s), p); err == nil {
		t.Fatal("unregistered policy acquired execution preparation")
	}
	input := featureRegistryInput()
	changed := input.operations[0]
	changed.VersionPolicy = identity.FeatureVersionSnapshotImport
	input.operations = append(input.operations, changed)
	if registry, err := NewContributorRegistry([]Contributor{input}); err == nil || registry != nil {
		t.Fatal("one schema declared conflicting version policies")
	}
}

func TestFeatureSnapshotImportLifecycleRetainsSourceVersion(t *testing.T) {
	for _, source := range []uint64{3, math.MaxUint64} {
		w, _, _ := auditFixture(t)
		op := featureCodecSpec().Operation
		op.VersionPolicy = identity.FeatureVersionSnapshotImport
		w.state.feature = &FeatureRegistration{Operation: op}
		w.state.subjectType = "api_key"
		p := LifecyclePlan{EventType: "api_key.imported.v1", AfterVersion: source}
		if err := bindLifecyclePlan(w, &p); err != nil || w.state.lifecycle == nil || w.state.lifecycle.plan.AfterVersion != source {
			t.Fatal("native lifecycle reset or rejected imported source version", source, err)
		}
	}
}

func TestFeatureSnapshotImportObservedScopeConservesPolicy(t *testing.T) {
	s := featureCodecSpec()
	s.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
	for _, subject := range []identity.FeatureSubjectRequirement{identity.FeatureSubjectUser, identity.FeatureSubjectAnonymousFlow} {
		s.Operation.SubjectRequirement = subject
		if subject == identity.FeatureSubjectAnonymousFlow {
			s.Binding.UserID, s.Binding.AnonymousFlowID = "", "flow-a"
		}
		wire := commandSafeFields(s.Binding, &s.Operation)
		binding, operation, err := decodeObservedScope(wire)
		if err != nil || binding != s.Binding || operation == nil || *operation != s.Operation {
			t.Fatal("historical command scope lost exact import policy", err)
		}
		for _, bad := range []uint64{0, 2, 256, math.MaxUint64} {
			changed := bytes.Replace(wire, append(cborText("version_policy"), 1), append(cborText("version_policy"), cborUint(bad)...), 1)
			if _, operation, err := decodeObservedScope(changed); err == nil || operation != nil {
				t.Fatal("unknown or explicitly default policy accepted as imported history")
			}
		}
	}
}

func TestFeatureSnapshotImportHistoricalPolicyCannotBeReinterpreted(t *testing.T) {
	for _, subject := range []identity.FeatureSubjectRequirement{identity.FeatureSubjectUser, identity.FeatureSubjectAnonymousFlow} {
		_, command, p := featurePlanFixture(t)
		s, _ := command.Feature()
		s.Operation.VersionPolicy = identity.FeatureVersionSnapshotImport
		s.Operation.SubjectRequirement = subject
		if subject == identity.FeatureSubjectAnonymousFlow {
			s.Binding.UserID, s.Binding.AnonymousFlowID = "", "flow-a"
		}
		p.Feature.Operation = s.Operation
		p.Lifecycle.AfterVersion = 3
		wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire)
		if err != nil || decoded.Feature.Operation != s.Operation {
			t.Fatal("historical subject/policy lost", err)
		}
		for _, replacement := range [][]byte{{0}, {2}, {24, 1}, {255}} {
			old := append(cborText("version_policy"), 1)
			bad := bytes.Replace(wire, old, append(cborText("version_policy"), replacement...), 1)
			if bytes.Equal(wire, bad) {
				t.Fatal("policy-tampering challenge did not change the encoded plan")
			}
			if _, err := decodeFeaturePlan(s.Binding, [32]byte{1}, bad); err == nil {
				t.Fatal("unknown, default or noncanonical import policy reinterpreted source history")
			}
		}
		for i := range wire {
			if _, err := decodeFeaturePlan(s.Binding, [32]byte{1}, wire[:i]); err == nil {
				t.Fatal("truncated imported history accepted")
			}
		}
	}
}
