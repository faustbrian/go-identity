package identity

import (
	"crypto/sha256"
	"fmt"
)

// PrivacyExportFragmentClassification is closed; absence must be proved, not
// inferred from a missing response, empty data, cancellation or unavailable cut.
type PrivacyExportFragmentClassification string

const (
	// PrivacyExportFragmentData binds nonempty canonical redacted content.
	PrivacyExportFragmentData PrivacyExportFragmentClassification = "data"
	// PrivacyExportFragmentNotApplicable binds exact absence at the requested cut.
	PrivacyExportFragmentNotApplicable PrivacyExportFragmentClassification = "not-applicable"
)

// PrivacyExportFragmentV1 is exact returned metadata, never publication authority.
// The contributor owns canonical redaction/content schema and exact-cut reads;
// the coordinator must validate this binding and independently verify observed
// bytes before any publication. All schema/contract/checkpoint versions are 1.0.
// Content itself remains caller-owned, not retained here. Never log this value.
type PrivacyExportFragmentV1 struct {
	ExportID            PrivacyExportJobID
	TenantID            TenantID
	SubjectID           UserID
	CommandID           CommandID
	PrivacyEpoch        uint64
	EvidenceKeyVersion  uint32
	SnapshotDigest      [32]byte
	ContributorID       string
	ContractMajor       uint16
	ContractMinor       uint16
	ProjectionID        PrivacyExportProjectionV1
	ScopeKeyDigest      [32]byte
	RequestedCheckpoint PrivacyExportCheckpointV1
	ObservedCheckpoint  PrivacyExportCheckpointV1
	SchemaMajor         uint16
	SchemaMinor         uint16
	Classification      PrivacyExportFragmentClassification
	ContentLength       uint64
	ContentDigest       [32]byte
}

// ValidateFragment checks the complete scope/version-vector binding, declared
// byte bound and digest of the actual canonical bytes. MaximumBytes is positive
// and at most 1 GiB. Bounds precede hashing; no bytes are copied or retained.
// NotApplicable requires zero bytes and SHA-256(empty); Data forbids empty data.
// This does not prove JSON canonicalization, schema/redaction or exact-cut reads:
// those are required from the registered contributor and composed coordinator.
// A valid fragment never authorizes download, publication or cascade closure.
func (s PrivacyExportSnapshotV1) ValidateFragment(f PrivacyExportFragmentV1, canonical []byte, maximumBytes uint64) error {
	if s.record == nil || maximumBytes == 0 || maximumBytes > 1<<30 || uint64(len(canonical)) > maximumBytes || f.ContentLength != uint64(len(canonical)) {
		return ErrInvalidPrivacyExportFragment
	}
	r := s.record
	b, exists := s.Contributor(f.ContributorID)
	if !exists || f.ExportID != r.ExportID || f.TenantID != r.TenantID || f.SubjectID != r.SubjectID || f.CommandID != r.CommandID || f.PrivacyEpoch != r.PrivacyEpoch || f.EvidenceKeyVersion != r.EvidenceKeyVersion || f.SnapshotDigest != r.Digest || f.ContractMajor != b.ContractMajor || f.ContractMinor != b.ContractMinor || f.ProjectionID != b.ProjectionID || f.ScopeKeyDigest != b.ScopeKeyDigest || f.RequestedCheckpoint != b.Checkpoint || f.ObservedCheckpoint != b.Checkpoint || f.SchemaMajor != 1 || f.SchemaMinor != 0 {
		return ErrInvalidPrivacyExportFragment
	}
	switch f.Classification {
	case PrivacyExportFragmentData:
		if f.ContentLength == 0 {
			return ErrInvalidPrivacyExportFragment
		}
	case PrivacyExportFragmentNotApplicable:
		if f.ContentLength != 0 {
			return ErrInvalidPrivacyExportFragment
		}
	default:
		return ErrInvalidPrivacyExportFragment
	}
	if sha256.Sum256(canonical) != f.ContentDigest {
		return ErrInvalidPrivacyExportFragment
	}
	return nil
}

func (PrivacyExportFragmentV1) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.PrivacyExportFragmentV1(redacted)"))
}
