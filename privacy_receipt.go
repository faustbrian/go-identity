package identity

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

// PrivacyExportStatus is the closed export-job state, not a command commit
// outcome or proof of object erasure. Empty and unknown strings are invalid.
// A request receipt is always queued; only the durable worker and lifecycle
// owners may transition a job through the remaining states.
type PrivacyExportStatus string

const (
	// PrivacyExportQueued records admission pending contributor work.
	PrivacyExportQueued PrivacyExportStatus = "queued"
	// PrivacyExportRunning records a leased job, not completed publication.
	PrivacyExportRunning PrivacyExportStatus = "running"
	// PrivacyExportReady requires complete fragments and sealed publication.
	PrivacyExportReady PrivacyExportStatus = "ready"
	// PrivacyExportFailed denies download and requires object reconciliation.
	PrivacyExportFailed PrivacyExportStatus = "failed"
	// PrivacyExportCancelled denies download; it does not attest object erasure.
	PrivacyExportCancelled PrivacyExportStatus = "cancelled"
	// PrivacyExportExpired denies download and outstanding capabilities.
	PrivacyExportExpired PrivacyExportStatus = "expired"
)

// PrivacyExportRequestReceipt retains immutable queued-admission metadata in
// the existing command journal. Snapshot is the complete durable record, not
// an opaque value that would serialize as an empty object. Treat this mutable
// reconstruction shape as sensitive, caller-owned data; never log it or mutate
// it concurrently. Formatting is redacted. Structural validation is not MAC
// verification, authoritative cut capture, current eligibility or publication.
// Admission retains the captured user version and advances privacy epoch once;
// it does not invent an unrelated user/authority-version increment.
type PrivacyExportRequestReceipt struct {
	Status                   PrivacyExportStatus
	Snapshot                 PrivacyExportSnapshotRecordV1
	ExpectedAuthorityVersion uint64
	ExpectedPrivacyEpoch     uint64
	MaximumBytes             uint64
	ArtifactTTL              time.Duration
	IntentDigest             [32]byte
}

// Format redacts scoped snapshots and retained request metadata for every verb.
func (PrivacyExportRequestReceipt) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.PrivacyExportRequestReceipt(redacted)")
}

func validPrivacyExportRequestBinding(b CommandBinding) bool {
	if !validCommandBinding(b) || b.OperationID != privacyExportRequestOperation || b.SchemaID != "identity-privacy-export" || b.SchemaVersion != 1 || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) {
		return false
	}
	// Do not silently rewrite imported directory IDs into the V1 wire profile.
	if _, ok := decodeID(string(b.TenantID)); !ok {
		return false
	}
	_, ok := decodeID(string(b.UserID))
	return ok
}

func validPrivacyArtifactPolicy(bytes uint64, ttl time.Duration) bool {
	return bytes >= 1<<20 && bytes <= 1<<30 && ttl >= 15*time.Minute && ttl <= 7*24*time.Hour && ttl%time.Second == 0
}

func validPrivacyExportResult(r CommandResult) bool {
	if !validPrivacyExportRequestBinding(r.Binding) || r.Feature != nil || r.Profile != nil || r.Revocation != nil || r.Unlink != nil || r.Link != nil || r.Identifier != nil || r.User != (User{}) || r.ExpectedVersion != 0 {
		return false
	}
	switch r.Outcome {
	case CommitOutcomeCommitted:
		p := r.PrivacyExport
		if p == nil || r.RetryAfter != 0 || !validDirectoryID(r.AuditEventID) || p.Status != PrivacyExportQueued || p.ExpectedAuthorityVersion == 0 || !unlinkVersion(p.ExpectedPrivacyEpoch) || !validPrivacyArtifactPolicy(p.MaximumBytes, p.ArtifactTTL) || p.IntentDigest == ([32]byte{}) || !validPrivacySnapshotRecordV1(p.Snapshot) || p.Snapshot.Digest == ([32]byte{}) {
			return false
		}
		s := p.Snapshot
		if s.CommandID != r.Binding.CommandID || s.TenantID != r.Binding.TenantID || s.SubjectID != r.Binding.UserID || s.PrivacyEpoch != p.ExpectedPrivacyEpoch+1 {
			return false
		}
		for _, contributor := range s.Contributors {
			if contributor.ScopeKeyDigest == ([32]byte{}) {
				return false
			}
		}
		return true
	case CommitOutcomeNotCommitted, CommitOutcomeUnknown, CommitOutcomeConflict:
		return r.PrivacyExport == nil && r.AuditEventID == "" && r.RetryAfter == 0
	case CommitOutcomeInProgress:
		return r.PrivacyExport == nil && r.AuditEventID == "" && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		return false
	}
}

// ValidatePrivacyExportRequest checks an exact receipt against retained request
// intent and, for committed admission, verifies the complete snapshot with its
// recorded evidence key. It returns an immutable copied snapshot only on a
// structurally committed queued admission. Known noncommitted outcomes return
// zero snapshot and nil error without requiring an unused evidence key. Invalid
// values return redacted InvalidInputError. The request need not carry a live
// Grant: recovery must match the original intent even after proof expiry.
// This does not prove a commit, authorization, fresh session, primary reads or
// captured cuts; the platform-owned service/adapter must establish those facts.
// No IO, proof consumption or job transition occurs. Do not mutate arguments
// concurrently. The returned snapshot cannot be changed through receipt aliases.
func (r CommandResult) ValidatePrivacyExportRequest(c PrivacyExportRequestCommand, key PrivacyExportEvidenceKey) (PrivacyExportSnapshotV1, error) {
	invalid := InvalidInputError{Field: "privacy_export_receipt"}
	if !validPrivacyExportRequest(c) || r.Validate() != nil || r.Binding != c.Binding {
		return PrivacyExportSnapshotV1{}, invalid
	}
	if r.Outcome != CommitOutcomeCommitted {
		return PrivacyExportSnapshotV1{}, nil
	}
	p := r.PrivacyExport
	digest, err := PrivacyExportIntentDigest(c)
	if err != nil || p.IntentDigest != digest || p.ExpectedAuthorityVersion != c.ExpectedAuthorityVersion || p.ExpectedPrivacyEpoch != c.ExpectedPrivacyEpoch || p.Snapshot.IdentityVersion != c.ExpectedIdentityVersion || p.MaximumBytes != c.MaximumBytes || p.ArtifactTTL != c.ArtifactTTL {
		return PrivacyExportSnapshotV1{}, invalid
	}
	for i, projection := range c.Projections {
		if p.Snapshot.Contributors[i].ContributorID != projection.ContributorID || p.Snapshot.Contributors[i].ProjectionID != projection.ProjectionID {
			return PrivacyExportSnapshotV1{}, invalid
		}
	}
	snapshot, err := key.VerifySnapshotV1(p.Snapshot)
	if err != nil {
		return PrivacyExportSnapshotV1{}, invalid
	}
	return snapshot, nil
}
