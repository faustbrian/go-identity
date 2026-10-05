package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

const privacyExportRequestOperation = "identity.privacy-export.request"

// PrivacyExportProjectionSpecV1 declares the immutable projection profile for
// one contributor. It cannot submit a checkpoint: the durable request owner
// captures that cut under its admission transaction, never from caller input.
type PrivacyExportProjectionSpecV1 struct {
	ContributorID string
	ProjectionID  PrivacyExportProjectionV1
}

// PrivacyExportRequestCommand binds full-subject portable-JSON export intent.
// A trusted service must authorize the current human, verify configured proof
// issuer/audience/freshness and retain the original opaque proof for the durable
// owner. The owner must repeat those checks under locks, match all expected
// versions, allocate export ID and the next privacy epoch, capture all cuts,
// reserve/use the proof atomically, and persist queued admission. Construction
// does none of that and does not enable a worker or expose data. Concurrent
// mutation during construction is forbidden; Command owns a copied projection
// slice. Format is redacted. No arbitrary scope, format, cut or callback exists.
type PrivacyExportRequestCommand struct {
	Binding                  CommandBinding
	ExpectedIdentityVersion  uint64
	ExpectedAuthorityVersion uint64
	ExpectedPrivacyEpoch     uint64
	SessionID                string
	SessionVersion           uint64
	MaximumBytes             uint64
	ArtifactTTL              time.Duration
	Projections              []PrivacyExportProjectionSpecV1
	Proof                    capability.Grant
}

func validPrivacyExportRequest(c PrivacyExportRequestCommand) bool {
	b := c.Binding
	if !validCommandBinding(b) || b.OperationID != privacyExportRequestOperation || b.SchemaID != "identity-privacy-export" || b.SchemaVersion != 1 || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || c.ExpectedIdentityVersion == 0 || c.ExpectedAuthorityVersion == 0 || !unlinkVersion(c.ExpectedPrivacyEpoch) || !validDirectoryID(c.SessionID) || c.SessionVersion == 0 || c.MaximumBytes < 1<<20 || c.MaximumBytes > 1<<30 || c.ArtifactTTL < 15*time.Minute || c.ArtifactTTL > 7*24*time.Hour || c.ArtifactTTL%time.Second != 0 {
		return false
	}
	// Snapshot V1 IDs are stricter than the existing directory profile. Do not
	// silently convert imported IDs: durable admission needs an explicit mapping.
	if _, ok := decodeID(string(b.TenantID)); !ok {
		return false
	}
	if _, ok := decodeID(string(b.UserID)); !ok {
		return false
	}
	owners := PrivacyExportContributorsV1()
	if len(c.Projections) != len(owners) {
		return false
	}
	for i, p := range c.Projections {
		if p.ContributorID != owners[i] || (p.ProjectionID != PrivacyExportSubjectJournalV1 && p.ProjectionID != PrivacyExportStagedSubjectV1) {
			return false
		}
	}
	return true
}

// PrivacyExportIntentDigest binds every unsigned field to a deterministic
// domain-separated SHA-256 digest. This is a proof caveat, not authorization,
// an export snapshot or a receipt. Proof metadata itself is excluded. See
// docs/privacy-snapshot.md for the closed CBOR profile. Invalid input is redacted.
func PrivacyExportIntentDigest(c PrivacyExportRequestCommand) ([32]byte, error) {
	if !validPrivacyExportRequest(c) {
		return [32]byte{}, InvalidInputError{Field: "privacy_export_intent"}
	}
	b := c.Binding
	out := []byte("identity-privacy-export-request-v1\x00")
	out = privacyCBORHead(out, 4, 20)
	for _, s := range []string{string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.ActorID), string(b.ActorKind), b.OperationID, b.PolicyID} {
		out = privacyCBORText(out, s)
	}
	out = privacyCBORHead(out, 0, b.PolicyVersion)
	out = privacyCBORText(out, b.SchemaID)
	out = privacyCBORHead(out, 0, uint64(b.SchemaVersion))
	out = privacyCBORText(out, b.CorrelationID)
	for _, n := range []uint64{c.ExpectedIdentityVersion, c.ExpectedAuthorityVersion, c.ExpectedPrivacyEpoch} {
		out = privacyCBORHead(out, 0, n)
	}
	out = privacyCBORText(out, c.SessionID)
	for _, n := range []uint64{c.SessionVersion, c.MaximumBytes, uint64(c.ArtifactTTL / time.Second)} {
		out = privacyCBORHead(out, 0, n)
	}
	out = privacyCBORText(out, "identity-portable-json-v1")
	out = privacyCBORHead(out, 4, uint64(len(c.Projections)))
	for _, p := range c.Projections {
		out = privacyCBORHead(out, 4, 2)
		out = privacyCBORText(out, p.ContributorID)
		out = privacyCBORText(out, string(p.ProjectionID))
	}
	return sha256.Sum256(out), nil
}

func privacyExportCaveats(c PrivacyExportRequestCommand) map[string]string {
	digest, _ := PrivacyExportIntentDigest(c)
	return map[string]string{"intent_digest": hex.EncodeToString(digest[:])}
}

// NewPrivacyExportRequestCommand validates and freezes exact signed metadata.
// It does not verify issuer trust, proof time, session freshness, authorization
// or storage. It never consumes proof. Only actual admission through the owned
// service and durable UnitOfWork can make an export runnable. This metadata-only
// constructor cannot manufacture original opaque proof custody.
func NewPrivacyExportRequestCommand(c PrivacyExportRequestCommand) (Command, error) {
	if !validPrivacyExportRequest(c) {
		return Command{}, InvalidInputError{Field: "privacy_export_command"}
	}
	p := c.Proof.Payload()
	if !validDirectoryID(p.ID) || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || len(p.Caveats) != 1 || c.Proof.Authorize(capability.Use{Audience: p.Audiences[0], Subject: string(c.Binding.UserID), Tenant: string(c.Binding.TenantID), Resource: string(c.Binding.UserID), Operation: privacyExportRequestOperation, Caveats: privacyExportCaveats(c)}) != nil {
		return Command{}, InvalidInputError{Field: "privacy_export_proof"}
	}
	c.Projections = slices.Clone(c.Projections)
	return Command{privacy: &c}, nil
}

// RequestPrivacyExport returns an owned projection copy only for this variant.
// Contents are sensitive trusted-adapter input, never public diagnostics.
func (c Command) RequestPrivacyExport() (PrivacyExportRequestCommand, bool) {
	if c.privacy == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.identifier != nil || c.feature != nil {
		return PrivacyExportRequestCommand{}, false
	}
	r := *c.privacy
	r.Projections = slices.Clone(r.Projections)
	return r, true
}

// Format prevents signed intent, identifiers and session bindings from leaking.
func (PrivacyExportRequestCommand) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.PrivacyExportRequestCommand(redacted)")
}

// PrivacyExportProofSpec is unsigned trusted ceremony output. Command.Proof
// must be zero. Supplying it does not confer minting or reauthentication authority.
type PrivacyExportProofSpec struct {
	Command              PrivacyExportRequestCommand
	Issuer, Audience, ID string
	IssuedAt, ExpiresAt  time.Time
}

// BuildPrivacyExportProofPayload prepares one-use, exact-intent issuance after
// trusted composition has verified the human/session and policy. Instants must
// have whole-second precision and an exclusive expiry at most five minutes
// later. No clock, signing, authorization, I/O or consumption occurs here.
func BuildPrivacyExportProofPayload(s PrivacyExportProofSpec) (capability.Payload, error) {
	if !validPrivacyExportRequest(s.Command) || s.Command.Proof.Payload().ID != "" || !validClaimIssuer(s.Issuer) || len(s.Issuer) > 256 || !validDirectoryID(s.Audience) || !validDirectoryID(s.ID) || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || s.IssuedAt.UTC().Year() < 1 || s.ExpiresAt.UTC().Year() > 9999 || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > 5*time.Minute {
		return capability.Payload{}, InvalidInputError{Field: "privacy_export_proof_spec"}
	}
	c := s.Command
	return capability.Payload{Version: 1, Issuer: s.Issuer, Audiences: []string{s.Audience}, Subject: string(c.Binding.UserID), Tenant: string(c.Binding.TenantID), Resource: string(c.Binding.UserID), Operation: privacyExportRequestOperation, ID: s.ID, MaxUses: 1, IssuedAt: s.IssuedAt.UTC(), NotBefore: s.IssuedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), Caveats: privacyExportCaveats(c)}, nil
}
