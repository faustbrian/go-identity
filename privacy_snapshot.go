package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrInvalidPrivacyExportSnapshot redacts malformed or unauthenticated bindings.
	ErrInvalidPrivacyExportSnapshot = errors.New("identity: invalid privacy export snapshot")
	// ErrInvalidPrivacyExportFragment redacts mismatched fragment metadata/content.
	ErrInvalidPrivacyExportFragment = errors.New("identity: invalid privacy export fragment")
	// ErrPrivacyExportJobIDEntropy reports unavailable export ID entropy.
	ErrPrivacyExportJobIDEntropy = errors.New("identity: privacy export ID entropy unavailable")
)

// PrivacyExportJobID is a canonical nonzero 128-bit export identity. Possession
// grants neither download nor snapshot authority. Empty is invalid.
type PrivacyExportJobID string

// NewPrivacyExportJobID reads exactly 16 crypto/rand bytes; failures reveal no ID.
func NewPrivacyExportJobID() (PrivacyExportJobID, error) {
	id, err := newID(rand.Reader, ErrPrivacyExportJobIDEntropy)
	return PrivacyExportJobID(id), err
}

// ParsePrivacyExportJobID accepts only the canonical 22-byte unpadded encoding.
func ParsePrivacyExportJobID(raw string) (PrivacyExportJobID, error) {
	if _, ok := decodeID(raw); !ok {
		return "", ErrInvalidPrivacyExportSnapshot
	}
	return PrivacyExportJobID(raw), nil
}

// PrivacyExportProjectionV1 is a closed, storage-neutral immutable cut profile.
// Neither value names a table or permits reading mutable current state.
type PrivacyExportProjectionV1 string

const (
	// PrivacyExportSubjectJournalV1 requires exact subject-scoped append-only reads.
	PrivacyExportSubjectJournalV1 PrivacyExportProjectionV1 = "subject-journal-v1"
	// PrivacyExportStagedSubjectV1 requires a fragment staged in request admission.
	PrivacyExportStagedSubjectV1 PrivacyExportProjectionV1 = "staged-subject-fragment-v1"
)

// PrivacyExportContributorsV1 returns the exact immutable manifest's 23 ASCII-
// ordered semantic owners. Adapters and cache projections are not extra owners.
func PrivacyExportContributorsV1() []string {
	return []string{
		"audit", "authorization", "identity", "identity/anonymous", "identity/apikey",
		"identity/delivery", "identity/email", "identity/i18n", "identity/impersonation",
		"identity/mfa", "identity/oauth", "identity/otp", "identity/password", "identity/phone",
		"identity/risk", "identity/session", "oauth-server", "organization", "passkey",
		"scim", "scim/organization", "sso", "webauthn",
	}
}

// PrivacyExportCheckpointV1 is a primary visibility cut, not an aggregate version
// or timestamp. The initial empty projection commits position 1. Every earlier
// subject mutation must be visible; producers must retain this exact cut.
type PrivacyExportCheckpointV1 struct {
	Major    uint16
	Minor    uint16
	Position uint64
}

// PrivacyExportContributorCutV1 is trusted owner's captured input. Position is
// positive; constructing it proves no authoritative read or durable admission.
type PrivacyExportContributorCutV1 struct {
	ContributorID      string
	ProjectionID       PrivacyExportProjectionV1
	CheckpointPosition uint64
}

// PrivacyExportContributorBindingV1 binds one complete subject cut. Version 1
// uses contract/checkpoint 1.0 and the closed scope selector ["subject"] for
// every contributor: tenant, subject and contributor are separately MAC-bound.
type PrivacyExportContributorBindingV1 struct {
	ContributorID  string
	ContractMajor  uint16
	ContractMinor  uint16
	ProjectionID   PrivacyExportProjectionV1
	ScopeKeyDigest [32]byte
	Checkpoint     PrivacyExportCheckpointV1
}

// PrivacyExportSnapshotSpecV1 is structural input, never authority. Trusted
// admission must capture all cuts while locking the actual identity, rejecting
// pending destructive state, and persist the complete sealed record atomically.
// V1 wire IDs require canonical nonzero 128-bit IDs; this does not normalize or
// rewrite imported directory IDs. An imported-ID profile requires explicit
// scope/schema reconciliation before admission, never silent conversion.
// RequestedAtMicroseconds is PostgreSQL UTC within years 1..9999. All counters
// are positive. Cuts must already be in exact manifest ASCII order.
type PrivacyExportSnapshotSpecV1 struct {
	ExportID                PrivacyExportJobID
	TenantID                TenantID
	SubjectID               UserID
	CommandID               CommandID
	IdentityVersion         uint64
	PrivacyEpoch            uint64
	LifecycleSequence       uint64
	RequestedAtMicroseconds int64
	Cuts                    []PrivacyExportContributorCutV1
}

// PrivacyExportSnapshotRecordV1 is caller-owned durable metadata, not a sealed
// value. VerifySnapshotV1 reconstructs it only after full structural/MAC checks.
// It contains pseudonymous personal data; do not log or use as authorization.
type PrivacyExportSnapshotRecordV1 struct {
	SchemaMajor             uint16
	SchemaMinor             uint16
	ExportID                PrivacyExportJobID
	TenantID                TenantID
	SubjectID               UserID
	CommandID               CommandID
	IdentityVersion         uint64
	PrivacyEpoch            uint64
	LifecycleSequence       uint64
	ManifestVersion         uint32
	RequestedAtMicroseconds int64
	Contributors            []PrivacyExportContributorBindingV1
	EvidenceKeyVersion      uint32
	Digest                  [32]byte
}

// PrivacyExportSnapshotV1 is immutable integrity evidence, not current authority.
// It owns copied metadata, no IO, resources or goroutines. Concurrent reads are
// safe; zero is invalid. A valid MAC cannot prove a cut was read authoritatively,
// authorization, durable admission, worker eligibility or final publication.
type PrivacyExportSnapshotV1 struct {
	record *PrivacyExportSnapshotRecordV1
}

// Valid reports construction/reconstruction, not current identity eligibility.
func (s PrivacyExportSnapshotV1) Valid() bool { return s.record != nil }

// Record returns an owned deep copy. Zero returns zero; it cannot be persisted
// or converted into valid evidence without the complete retained key profile.
func (s PrivacyExportSnapshotV1) Record() PrivacyExportSnapshotRecordV1 {
	if s.record == nil {
		return PrivacyExportSnapshotRecordV1{}
	}
	r := *s.record
	r.Contributors = slices.Clone(r.Contributors)
	return r
}

// Contributor returns an immutable exact binding; unknown/unbounded IDs fail.
func (s PrivacyExportSnapshotV1) Contributor(id string) (PrivacyExportContributorBindingV1, bool) {
	if s.record != nil && len(id) > 0 && len(id) <= 32 {
		for _, b := range s.record.Contributors {
			if b.ContributorID == id {
				return b, true
			}
		}
	}
	return PrivacyExportContributorBindingV1{}, false
}

// PrivacyExportEvidenceKey owns a copied versioned independent 256-bit HMAC
// integrity key. Zero is invalid. Retain versions through snapshot/evidence
// retention; rotation never re-MACs old records or changes recorded cuts. Key
// possession is trusted composition authority, never caller-provided config.
// This value has no destroy/zeroization guarantee in Go; manage retention at
// the secret owner. Immutable copies are concurrent-safe; never serialize it.
type PrivacyExportEvidenceKey struct {
	version uint32
	key     [32]byte
}

// NewPrivacyExportEvidenceKey accepts positive version and nonzero key bytes.
// It validates structure, not key entropy, provenance or permission to seal.
func NewPrivacyExportEvidenceKey(version uint32, material [32]byte) (PrivacyExportEvidenceKey, error) {
	if version == 0 || material == [32]byte{} {
		return PrivacyExportEvidenceKey{}, ErrInvalidPrivacyExportSnapshot
	}
	return PrivacyExportEvidenceKey{version: version, key: material}, nil
}

func (k PrivacyExportEvidenceKey) valid() bool { return k.version > 0 && k.key != [32]byte{} }

// SealSnapshotV1 copies and authenticates the complete closed input. It performs
// no storage writes or authorization. Only actual command admission may make an
// export runnable; callers must not use this constructor to attest locks/cuts.
func (k PrivacyExportEvidenceKey) SealSnapshotV1(spec PrivacyExportSnapshotSpecV1) (PrivacyExportSnapshotV1, error) {
	if !k.valid() || !validPrivacySnapshotScope(spec) || len(spec.Cuts) != 23 {
		return PrivacyExportSnapshotV1{}, ErrInvalidPrivacyExportSnapshot
	}
	r := PrivacyExportSnapshotRecordV1{
		SchemaMajor: 1, ExportID: spec.ExportID, TenantID: spec.TenantID,
		SubjectID: spec.SubjectID, CommandID: spec.CommandID, IdentityVersion: spec.IdentityVersion,
		PrivacyEpoch: spec.PrivacyEpoch, LifecycleSequence: spec.LifecycleSequence,
		ManifestVersion: 1, RequestedAtMicroseconds: spec.RequestedAtMicroseconds,
		EvidenceKeyVersion: k.version,
	}
	for i, id := range PrivacyExportContributorsV1() {
		cut := spec.Cuts[i]
		if cut.ContributorID != id || !validPrivacyProjection(cut.ProjectionID) || cut.CheckpointPosition == 0 {
			return PrivacyExportSnapshotV1{}, ErrInvalidPrivacyExportSnapshot
		}
		r.Contributors = append(r.Contributors, PrivacyExportContributorBindingV1{
			ContributorID: id, ContractMajor: 1, ProjectionID: cut.ProjectionID,
			ScopeKeyDigest: k.scopeDigest(r.TenantID, r.SubjectID, id),
			Checkpoint:     PrivacyExportCheckpointV1{Major: 1, Position: cut.CheckpointPosition},
		})
	}
	r.Digest = k.mac("identity-privacy-export-snapshot-v1", privacySnapshotCBOR(r))
	return PrivacyExportSnapshotV1{record: &r}, nil
}

// VerifySnapshotV1 reconstructs only exact V1 records under their retained key.
// Missing members, unknown versions, changed checkpoints or any MAC mismatch
// return zero. It never repairs, reorders, defaults, upgrades or renews evidence.
func (k PrivacyExportEvidenceKey) VerifySnapshotV1(r PrivacyExportSnapshotRecordV1) (PrivacyExportSnapshotV1, error) {
	if !k.valid() || r.EvidenceKeyVersion != k.version || !validPrivacySnapshotRecordV1(r) {
		return PrivacyExportSnapshotV1{}, ErrInvalidPrivacyExportSnapshot
	}
	for _, b := range r.Contributors {
		want := k.scopeDigest(r.TenantID, r.SubjectID, b.ContributorID)
		if !hmac.Equal(want[:], b.ScopeKeyDigest[:]) {
			return PrivacyExportSnapshotV1{}, ErrInvalidPrivacyExportSnapshot
		}
	}
	want := k.mac("identity-privacy-export-snapshot-v1", privacySnapshotCBOR(r))
	if !hmac.Equal(want[:], r.Digest[:]) {
		return PrivacyExportSnapshotV1{}, ErrInvalidPrivacyExportSnapshot
	}
	r.Contributors = slices.Clone(r.Contributors)
	return PrivacyExportSnapshotV1{record: &r}, nil
}

// Structure is shared by receipt decoding and MAC verification, never used to
// attest integrity or cut provenance. MAC/scope-key comparison stays key-owned.
func validPrivacySnapshotRecordV1(r PrivacyExportSnapshotRecordV1) bool {
	if r.SchemaMajor != 1 || r.SchemaMinor != 0 || r.ManifestVersion != 1 || r.EvidenceKeyVersion == 0 || len(r.Contributors) != 23 {
		return false
	}
	spec := PrivacyExportSnapshotSpecV1{
		ExportID: r.ExportID, TenantID: r.TenantID, SubjectID: r.SubjectID, CommandID: r.CommandID,
		IdentityVersion: r.IdentityVersion, PrivacyEpoch: r.PrivacyEpoch,
		LifecycleSequence: r.LifecycleSequence, RequestedAtMicroseconds: r.RequestedAtMicroseconds,
	}
	if !validPrivacySnapshotScope(spec) {
		return false
	}
	for i, id := range PrivacyExportContributorsV1() {
		b := r.Contributors[i]
		if b.ContributorID != id || b.ContractMajor != 1 || b.ContractMinor != 0 || !validPrivacyProjection(b.ProjectionID) || b.Checkpoint.Major != 1 || b.Checkpoint.Minor != 0 || b.Checkpoint.Position == 0 {
			return false
		}
	}
	return true
}

func validPrivacySnapshotScope(s PrivacyExportSnapshotSpecV1) bool {
	for _, id := range []string{string(s.ExportID), string(s.TenantID), string(s.SubjectID), string(s.CommandID)} {
		if _, ok := decodeID(id); !ok {
			return false
		}
	}
	return s.IdentityVersion > 0 && s.PrivacyEpoch > 0 && s.LifecycleSequence > 0 && s.RequestedAtMicroseconds >= -62135596800000000 && s.RequestedAtMicroseconds <= 253402300799999999
}

func validPrivacyProjection(p PrivacyExportProjectionV1) bool {
	return p == PrivacyExportSubjectJournalV1 || p == PrivacyExportStagedSubjectV1
}

func (k PrivacyExportEvidenceKey) mac(domain string, wire []byte) [32]byte {
	m := hmac.New(sha256.New, k.key[:])
	_, _ = m.Write([]byte(domain))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write(wire)
	var digest [32]byte
	copy(digest[:], m.Sum(nil))
	return digest
}

func (k PrivacyExportEvidenceKey) scopeDigest(tenant TenantID, subject UserID, contributor string) [32]byte {
	b := privacyCBORHead(nil, 4, 4)
	b = privacyCBORText(b, string(tenant))
	b = privacyCBORText(b, string(subject))
	b = privacyCBORText(b, contributor)
	b = privacyCBORText(privacyCBORHead(b, 4, 1), "subject")
	return k.mac("identity-privacy-export-scope-v1", b)
}

// The V1 canonical tuple follows Record field order with Digest omitted. All
// strings/collections are closed and bounded before this encoder is reached.
// RFC 8949 preferred serialization: definite arrays, shortest integers/lengths,
// text for canonical IDs/enums, byte strings for digests, no maps/tags/floats.
func privacySnapshotCBOR(r PrivacyExportSnapshotRecordV1) []byte {
	b := privacyCBORHead(nil, 4, 13)
	b = privacyCBORHead(b, 0, uint64(r.SchemaMajor))
	b = privacyCBORHead(b, 0, uint64(r.SchemaMinor))
	for _, id := range []string{string(r.ExportID), string(r.TenantID), string(r.SubjectID), string(r.CommandID)} {
		b = privacyCBORText(b, id)
	}
	for _, n := range []uint64{r.IdentityVersion, r.PrivacyEpoch, r.LifecycleSequence, uint64(r.ManifestVersion)} {
		b = privacyCBORHead(b, 0, n)
	}
	if r.RequestedAtMicroseconds < 0 {
		b = privacyCBORHead(b, 1, uint64(-(r.RequestedAtMicroseconds + 1)))
	} else {
		b = privacyCBORHead(b, 0, uint64(r.RequestedAtMicroseconds))
	}
	b = privacyCBORHead(b, 4, uint64(len(r.Contributors)))
	for _, binding := range r.Contributors {
		b = privacyCBORHead(b, 4, 8)
		b = privacyCBORText(b, binding.ContributorID)
		b = privacyCBORHead(b, 0, uint64(binding.ContractMajor))
		b = privacyCBORHead(b, 0, uint64(binding.ContractMinor))
		b = privacyCBORText(b, string(binding.ProjectionID))
		b = append(privacyCBORHead(b, 2, 32), binding.ScopeKeyDigest[:]...)
		b = privacyCBORHead(b, 0, uint64(binding.Checkpoint.Major))
		b = privacyCBORHead(b, 0, uint64(binding.Checkpoint.Minor))
		b = privacyCBORHead(b, 0, binding.Checkpoint.Position)
	}
	return privacyCBORHead(b, 0, uint64(r.EvidenceKeyVersion))
}

func privacyCBORText(b []byte, value string) []byte {
	return append(privacyCBORHead(b, 3, uint64(len(value))), value...)
}

func privacyCBORHead(b []byte, major byte, n uint64) []byte {
	base := major << 5
	switch {
	case n < 24:
		return append(b, base|byte(n))
	case n <= 0xff:
		return append(b, base|24, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(b, base|25), uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(b, base|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(b, base|27), n)
	}
}

func (PrivacyExportEvidenceKey) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.PrivacyExportEvidenceKey(redacted)"))
}
func (PrivacyExportSnapshotV1) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.PrivacyExportSnapshotV1(redacted)"))
}
func (PrivacyExportSnapshotSpecV1) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.PrivacyExportSnapshotSpecV1(redacted)"))
}
func (PrivacyExportSnapshotRecordV1) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.PrivacyExportSnapshotRecordV1(redacted)"))
}
