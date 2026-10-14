package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func privacySnapshotFixture(t *testing.T) (PrivacyExportEvidenceKey, PrivacyExportSnapshotSpecV1) {
	t.Helper()
	key, err := NewPrivacyExportEvidenceKey(7, [32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	id := "AQEBAQEBAQEBAQEBAQEBAQ"
	spec := PrivacyExportSnapshotSpecV1{
		ExportID: PrivacyExportJobID(id), TenantID: TenantID(id), SubjectID: UserID(id),
		CommandID: CommandID(id), IdentityVersion: math.MaxUint64, PrivacyEpoch: 2,
		LifecycleSequence: 3, RequestedAtMicroseconds: -1,
	}
	for _, contributor := range PrivacyExportContributorsV1() {
		spec.Cuts = append(spec.Cuts, PrivacyExportContributorCutV1{
			ContributorID: contributor, ProjectionID: PrivacyExportSubjectJournalV1,
			CheckpointPosition: 1,
		})
	}
	return key, spec
}

func TestPrivacySnapshotExactManifestAndImmutableBinding(t *testing.T) {
	key, spec := privacySnapshotFixture(t)
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	record := snapshot.Record()
	if record.SchemaMajor != 1 || record.SchemaMinor != 0 || record.ManifestVersion != 1 || record.EvidenceKeyVersion != 7 || len(record.Contributors) != 23 {
		t.Fatal("snapshot lost its closed profile")
	}
	spec.Cuts[0].CheckpointPosition = 22
	record.Contributors[0].Checkpoint.Position = 33
	if snapshot.Record().Contributors[0].Checkpoint.Position != 1 {
		t.Fatal("snapshot aliased caller storage")
	}
	verified, err := key.VerifySnapshotV1(snapshot.Record())
	if err != nil || verified.Record().Digest != snapshot.Record().Digest {
		t.Fatal("durable reconstruction failed", err)
	}
	manifest := PrivacyExportContributorsV1()
	manifest[0] = "changed"
	if PrivacyExportContributorsV1()[0] != "audit" {
		t.Fatal("manifest mutable")
	}
	for _, mutate := range []func(*PrivacyExportSnapshotSpecV1){
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts = s.Cuts[:22] },
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts = append(s.Cuts, s.Cuts[0]) },
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts[1] = s.Cuts[0] },
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts[0].ContributorID = "unknown" },
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts[0].ProjectionID = "table-name" },
		func(s *PrivacyExportSnapshotSpecV1) { s.Cuts[0].CheckpointPosition = 0 },
		func(s *PrivacyExportSnapshotSpecV1) { s.TenantID = "wrong tenant" },
		func(s *PrivacyExportSnapshotSpecV1) { s.PrivacyEpoch = 0 },
		func(s *PrivacyExportSnapshotSpecV1) { s.IdentityVersion = 0 },
		func(s *PrivacyExportSnapshotSpecV1) { s.RequestedAtMicroseconds = math.MaxInt64 },
	} {
		_, bad := privacySnapshotFixture(t)
		mutate(&bad)
		if snapshot, err := key.SealSnapshotV1(bad); !errors.Is(err, ErrInvalidPrivacyExportSnapshot) || snapshot.Valid() {
			t.Fatal("invalid snapshot admitted")
		}
	}
}

func TestPrivacySnapshotTamperingAndUnavailableKeyDeny(t *testing.T) {
	key, spec := privacySnapshotFixture(t)
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PrivacyExportSnapshotRecordV1){
		func(r *PrivacyExportSnapshotRecordV1) { r.SubjectID = "AgICAgICAgICAgICAgICAg" },
		func(r *PrivacyExportSnapshotRecordV1) { r.IdentityVersion-- },
		func(r *PrivacyExportSnapshotRecordV1) { r.PrivacyEpoch++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.LifecycleSequence++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.RequestedAtMicroseconds++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.SchemaMinor++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.ManifestVersion++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.EvidenceKeyVersion++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.Contributors[0].ContractMinor++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.Contributors[0].Checkpoint.Major++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.Contributors[0].Checkpoint.Position++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.Contributors[0].ScopeKeyDigest[0]++ },
		func(r *PrivacyExportSnapshotRecordV1) { r.Digest[0]++ },
	} {
		r := snapshot.Record()
		mutate(&r)
		if s, err := key.VerifySnapshotV1(r); !errors.Is(err, ErrInvalidPrivacyExportSnapshot) || s.Valid() {
			t.Fatal("tampering accepted")
		}
	}
	other, err := NewPrivacyExportEvidenceKey(7, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := other.VerifySnapshotV1(snapshot.Record()); err == nil || s.Valid() {
		t.Fatal("another key accepted")
	}
	if s, err := (PrivacyExportEvidenceKey{}).SealSnapshotV1(spec); err == nil || s.Valid() {
		t.Fatal("zero key accepted")
	}
	for _, version := range []uint32{0, 1} {
		if _, err := NewPrivacyExportEvidenceKey(version, [32]byte{}); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, err := NewPrivacyExportEvidenceKey(0, [32]byte{1}); err == nil {
		t.Fatal("zero version accepted")
	}
	if strings.Contains(fmt.Sprintf("%#v", key), "1, 2, 3") || !strings.Contains(fmt.Sprintf("%+v", snapshot), "redacted") {
		t.Fatal("unsafe formatting")
	}
}

func privacyFragmentFixture(t *testing.T) (PrivacyExportSnapshotV1, PrivacyExportFragmentV1, []byte) {
	t.Helper()
	key, spec := privacySnapshotFixture(t)
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	r := snapshot.Record()
	b, ok := snapshot.Contributor("identity/i18n")
	if !ok {
		t.Fatal("missing i18n")
	}
	content := []byte(`{"locale":"fi","version":1,"noticeVersion":1,"checkpoint":1}`)
	f := PrivacyExportFragmentV1{
		ExportID: r.ExportID, TenantID: r.TenantID, SubjectID: r.SubjectID, CommandID: r.CommandID,
		PrivacyEpoch: r.PrivacyEpoch, EvidenceKeyVersion: r.EvidenceKeyVersion, SnapshotDigest: r.Digest,
		ContributorID: b.ContributorID, ContractMajor: b.ContractMajor, ContractMinor: b.ContractMinor,
		ProjectionID: b.ProjectionID, ScopeKeyDigest: b.ScopeKeyDigest,
		RequestedCheckpoint: b.Checkpoint, ObservedCheckpoint: b.Checkpoint,
		SchemaMajor: 1, SchemaMinor: 0, Classification: PrivacyExportFragmentData,
		ContentLength: uint64(len(content)), ContentDigest: sha256.Sum256(content),
	}
	return snapshot, f, content
}

func TestPrivacyFragmentRequiresExactSnapshotCutAndContent(t *testing.T) {
	snapshot, fragment, content := privacyFragmentFixture(t)
	if err := snapshot.ValidateFragment(fragment, content, 1024); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PrivacyExportFragmentV1){
		func(f *PrivacyExportFragmentV1) { f.SubjectID = "AgICAgICAgICAgICAgICAg" },
		func(f *PrivacyExportFragmentV1) { f.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(f *PrivacyExportFragmentV1) { f.PrivacyEpoch++ },
		func(f *PrivacyExportFragmentV1) { f.SnapshotDigest[0]++ },
		func(f *PrivacyExportFragmentV1) { f.ScopeKeyDigest[0]++ },
		func(f *PrivacyExportFragmentV1) { f.ContractMinor++ },
		func(f *PrivacyExportFragmentV1) { f.SchemaMinor++ },
		func(f *PrivacyExportFragmentV1) { f.ObservedCheckpoint.Position++ },
		func(f *PrivacyExportFragmentV1) { f.RequestedCheckpoint.Position++ },
		func(f *PrivacyExportFragmentV1) { f.ContributorID = "unknown" },
		func(f *PrivacyExportFragmentV1) { f.Classification = "unknown" },
		func(f *PrivacyExportFragmentV1) { f.ContentLength++ },
		func(f *PrivacyExportFragmentV1) { f.ContentDigest[0]++ },
	} {
		bad := fragment
		mutate(&bad)
		if err := snapshot.ValidateFragment(bad, content, 1024); !errors.Is(err, ErrInvalidPrivacyExportFragment) {
			t.Fatal("invalid fragment accepted")
		}
	}
	if err := snapshot.ValidateFragment(fragment, content, uint64(len(content)-1)); err == nil {
		t.Fatal("maximum bypassed")
	}
	if err := snapshot.ValidateFragment(fragment, append(content, 'x'), 1024); err == nil {
		t.Fatal("content mismatch accepted")
	}
	fragment.Classification = PrivacyExportFragmentNotApplicable
	fragment.ContentLength = 0
	fragment.ContentDigest = sha256.Sum256(nil)
	if err := snapshot.ValidateFragment(fragment, nil, 1024); err != nil {
		t.Fatal("proved absence rejected", err)
	}
	fragment.Classification = PrivacyExportFragmentData
	if err := snapshot.ValidateFragment(fragment, nil, 1024); err == nil {
		t.Fatal("empty data treated as absence")
	}
	if _, ok := snapshot.Contributor(strings.Repeat("x", 10000)); ok {
		t.Fatal("unknown contributor matched")
	}
}

// Numeric/byte/array fixtures are independently specified by RFC 8949 Appendix A.
// The encoder supports only this closed privacy tuple, not generic CBOR parsing.
func TestPrivacyCBORPreferredIntegerAndLengthEncoding(t *testing.T) {
	for _, fixture := range []struct {
		major byte
		value uint64
		wire  string
	}{
		{0, 0, "00"}, {0, 23, "17"}, {0, 24, "1818"}, {0, 255, "18ff"},
		{0, 256, "190100"}, {0, 1000, "1903e8"}, {0, 65536, "1a00010000"},
		{0, 1000000000000, "1b000000e8d4a51000"}, {0, math.MaxUint64, "1bffffffffffffffff"},
		{1, 0, "20"}, {1, 9, "29"}, {1, 99, "3863"},
		{2, 4, "44"}, {3, 1, "61"}, {4, 3, "83"},
	} {
		want, err := hex.DecodeString(fixture.wire)
		if err != nil {
			t.Fatal(err)
		}
		if got := privacyCBORHead(nil, fixture.major, fixture.value); !bytes.Equal(got, want) {
			t.Fatalf("integer/length encoding: %x != %x", got, want)
		}
	}
}

func TestPrivacyScopeMACUsesTheClosedDomainSeparatedTuple(t *testing.T) {
	key, spec := privacySnapshotFixture(t)
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	// Independently encoded [tenant, subject, "identity/i18n", ["subject"]].
	// ASCII ID bytes are text, not decoded byte strings. No secret input is used.
	wire := append([]byte{0x84, 0x76}, []byte("AQEBAQEBAQEBAQEBAQEBAQ")...)
	wire = append(wire, 0x76)
	wire = append(wire, []byte("AQEBAQEBAQEBAQEBAQEBAQ")...)
	wire = append(wire, 0x6d)
	wire = append(wire, []byte("identity/i18n")...)
	wire = append(wire, 0x81, 0x67)
	wire = append(wire, []byte("subject")...)
	material := [32]byte{1, 2, 3}
	mac := hmac.New(sha256.New, material[:])
	mac.Write([]byte("identity-privacy-export-scope-v1\x00"))
	mac.Write(wire)
	binding, ok := snapshot.Contributor("identity/i18n")
	if !ok || !bytes.Equal(binding.ScopeKeyDigest[:], mac.Sum(nil)) {
		t.Fatal("scope tuple/domain changed")
	}
	// The same content under snapshot's domain cannot masquerade as a scope MAC.
	if key.mac("identity-privacy-export-snapshot-v1", wire) == binding.ScopeKeyDigest {
		t.Fatal("missing domain separation")
	}
}

func TestPrivacySnapshotTimestampEdgesAndZeroValues(t *testing.T) {
	key, spec := privacySnapshotFixture(t)
	for _, requested := range []int64{-62135596800000000, 0, 253402300799999999} {
		spec.RequestedAtMicroseconds = requested
		snapshot, err := key.SealSnapshotV1(spec)
		if err != nil {
			t.Fatal("PostgreSQL timestamp edge rejected", err)
		}
		if _, err := key.VerifySnapshotV1(snapshot.Record()); err != nil {
			t.Fatal("edge reconstruction failed", err)
		}
	}
	for _, requested := range []int64{-62135596800000001, 253402300800000000, math.MinInt64} {
		spec.RequestedAtMicroseconds = requested
		if got, err := key.SealSnapshotV1(spec); err == nil || got.Valid() {
			t.Fatal("timestamp outside profile accepted")
		}
	}
	zero := PrivacyExportSnapshotV1{}
	if zero.Valid() || zero.Record().Contributors != nil {
		t.Fatal("zero snapshot usable")
	}
	if _, ok := zero.Contributor("identity"); ok {
		t.Fatal("zero snapshot yielded binding")
	}
	_, fragment, content := privacyFragmentFixture(t)
	if err := zero.ValidateFragment(fragment, content, 1024); err == nil {
		t.Fatal("zero snapshot accepted fragment")
	}
	if _, err := ParsePrivacyExportJobID("AAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("zero export ID accepted")
	}
	id, err := NewPrivacyExportJobID()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParsePrivacyExportJobID(string(id)); err != nil || got != id {
		t.Fatal("generated export ID noncanonical")
	}
}

func FuzzPrivacySnapshotTampering(f *testing.F) {
	f.Add(uint64(1), int64(-1), "identity/i18n")
	f.Fuzz(func(t *testing.T, position uint64, requested int64, contributor string) {
		key, spec := privacySnapshotFixture(t)
		spec.Cuts[0].CheckpointPosition = position
		spec.RequestedAtMicroseconds = requested
		snapshot, err := key.SealSnapshotV1(spec)
		if err != nil {
			if snapshot.Valid() {
				t.Fatal("failure returned snapshot")
			}
			return
		}
		reconstructed, err := key.VerifySnapshotV1(snapshot.Record())
		if err != nil || !reconstructed.Valid() {
			t.Fatal("valid reconstruction denied")
		}
		if binding, ok := snapshot.Contributor(contributor); ok && binding.ContributorID != contributor {
			t.Fatal("wrong contributor returned")
		}
		r := snapshot.Record()
		r.PrivacyEpoch++
		if got, err := key.VerifySnapshotV1(r); err == nil || got.Valid() {
			t.Fatal("mutated snapshot authenticated")
		}
	})
}
