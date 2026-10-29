package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// LegacySecret is a bounded historical bare credential for verification only.
// It has no reveal, issuance or serialization operation. Its bytes are hashed
// unchanged: no normalization, invented prefix or historical-format guessing.
type LegacySecret struct{ wire string }

// ParseLegacySecret accepts 1..4096 unchanged bytes before any hashing/copy.
// Parsing proves no authority and does not select the verification algorithm.
func ParseLegacySecret(wire string) (LegacySecret, error) {
	if len(wire) == 0 || len(wire) > 4096 {
		return LegacySecret{}, ErrInvalid
	}
	return LegacySecret{wire: strings.Clone(wire)}, nil
}

// LegacyDigest holds a historical SHA-256 verifier, never a bearer credential.
// The importer obtains it from authenticated source data, not a raw token.
// Copies are immutable; formatting and serialization redact the digest.
type LegacyDigest struct{ sum [32]byte }

// NewLegacyDigest admits exactly a nonzero SHA-256 verifier. It performs no
// credential verification, source authentication or durable import.
func NewLegacyDigest(sum [32]byte) (LegacyDigest, error) {
	if sum == ([32]byte{}) {
		return LegacyDigest{}, ErrInvalid
	}
	return LegacyDigest{sum: sum}, nil
}

// Sum returns digest-only persistence metadata, not plaintext. Consumers must
// not log it, expose it as authentication or substitute it for current policy.
func (d LegacyDigest) Sum() [32]byte                 { return d.sum }
func (d LegacyDigest) Validate() error               { _, err := NewLegacyDigest(d.sum); return err }
func (d LegacyDigest) Equal(other LegacyDigest) bool { return hmac.Equal(d.sum[:], other.sum[:]) }

// Digest computes precisely historical SHA-256 only under a valid, explicit
// server-selected legacy configuration. Disabled configurations remain
// representable for retained metadata; they cannot authorize verification.
func (s LegacySecret) Digest(c Configuration) (LegacyDigest, error) {
	if s.wire == "" || c.Validate() != nil || c.spec.Algorithm != AlgorithmLegacySHA256V1 {
		return LegacyDigest{}, ErrInvalid
	}
	return NewLegacyDigest(sha256.Sum256([]byte(s.wire)))
}

// ImportRequest is one authenticated self-owned digest-only source snapshot.
// Record preserves the supplied canonical ID, owner, versions, grant, absolute
// times, terminal status and replacement lineage. SourceVersion orders source
// snapshots; it never confers human, tenant or directory authority. Import is
// not issuance and must emit no created-key/billing event or reveal material.
type ImportRequest struct {
	Authentication Authentication
	IdempotencyKey identity.IdempotencyKey
	Record         Record
	Digest         LegacyDigest
	SourceID       string
	SourceVersion  uint64
	CorrelationID  string
	Network        string
}

// StaleImportError identifies an older authenticated source snapshot. It never
// discloses the current source version, owner, digest or key existence publicly.
// A rejected snapshot has no authority and cannot replace a retained tombstone.
type StaleImportError struct{}

func (StaleImportError) Error() string { return "apikey: stale import" }

// Validate checks bounded shape and selected metadata only. Native import must
// authenticate the real current human, authorize this exact owner/source and
// every immutable permission, validate canonical IDs through configured policy,
// and atomically fence source versions, tombstones and current authority.
func (r ImportRequest) Validate(c Configuration) error {
	if r.Authentication.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || c.Validate() != nil || c.spec.Algorithm != AlgorithmLegacySHA256V1 || c.spec.State != ConfigurationVerifyOnly || r.Record.Validate(c) != nil || r.Record.Owner.spec.Kind != OwnerUser || r.Record.Owner.spec.TenantID != r.Authentication.TenantID || !utf8.ValidString(r.Record.Name) || !importTime(r.Record.CreatedAt) || !importTime(r.Record.ExpiresAt) || r.Digest.Validate() != nil || !scope(r.SourceID, 128) || r.SourceVersion == 0 || len(r.CorrelationID) > 128 || !canonicalNetwork(r.Network) {
		return ErrInvalid
	}
	return nil
}

func importTime(t time.Time) bool {
	u := t.UTC()
	return !u.IsZero() && u.Year() >= 1 && u.Year() <= 9999 && u.Nanosecond()%1000 == 0
}

// LegacyImporter adds digest-only migration without changing the supported
// modern Service interface. Original retries/recovery must use the existing
// coordinator and return status only, never execute a replacement command.
type LegacyImporter interface {
	Import(context.Context, ImportRequest) (identity.CommandResult, error)
}

func (LegacySecret) Format(s fmt.State, _ rune)    { io.WriteString(s, "[REDACTED]") }
func (LegacySecret) MarshalJSON() ([]byte, error)  { return nil, ErrDisclosure }
func (LegacySecret) MarshalText() ([]byte, error)  { return nil, ErrDisclosure }
func (LegacySecret) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (LegacyDigest) Format(s fmt.State, _ rune)    { io.WriteString(s, "apikey.LegacyDigest(redacted)") }
func (LegacyDigest) MarshalJSON() ([]byte, error)  { return nil, ErrDisclosure }
func (LegacyDigest) MarshalText() ([]byte, error)  { return nil, ErrDisclosure }
func (LegacyDigest) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (ImportRequest) Format(s fmt.State, _ rune)   { io.WriteString(s, "apikey.ImportRequest(redacted)") }
func (ImportRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (ImportRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
