// Package apikey owns API-key secret custody, immutable grants and
// current-authority reduction. Durable workflows are supplied by owned adapters,
// not application-written stores. The selected profile is user-owned, uncached
// and unlimited; other profiles must not silently fall back to it.
package apikey

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

var (
	ErrInvalid         = errors.New("apikey: invalid input")
	ErrDenied          = errors.New("apikey: denied")
	ErrDisclosure      = errors.New("apikey: disclosure forbidden")
	ErrAlreadyRevealed = errors.New("apikey: already revealed")
	ErrNoReduction     = errors.New("apikey: no permission reduction")
)

// KeyID is a bounded durable identity, not a credential or generator policy.
// Existing canonical IDs, including ULIDs, must remain unchanged. The native
// composition separately owns canonical-ID policy and authenticated source maps.
type KeyID string

// NewKeyID creates a modern random ID independently of the durable ID policy.
// Existing canonical IDs are restored unchanged through ParseKeyID.
func NewKeyID() (KeyID, error) {
	id, err := identity.NewCommandID()
	if err != nil {
		return "", ErrInvalid
	}
	return KeyID(id), nil
}

// ParseKeyID validates bounded opaque identity shape without generating,
// normalizing or looking up a key. It does not certify source canonicalization.
func ParseKeyID(raw string) (KeyID, error) {
	if !scope(raw, 128) {
		return "", ErrInvalid
	}
	return KeyID(strings.Clone(raw)), nil
}

// OwnerKind is a closed tagged identity. OwnerOrganization is represented but
// not enabled by the initial native user-owned profile.
type OwnerKind uint8

const (
	OwnerKindUnspecified OwnerKind = iota
	OwnerUser
	OwnerOrganization
)

// OrganizationID preserves a canonical organization identity separately from a
// user ID. Construction establishes shape, never organization authority.
type OrganizationID string

// OwnerSpec binds exactly one identity arm and its positive authority epoch.
// Version is the owner security epoch, not its directory row revision. For an
// organization it is the terminal credential-revocation epoch, not the policy
// or membership epoch: a newer value cannot authorize an older credential.
type OwnerSpec struct {
	TenantID       identity.TenantID
	Kind           OwnerKind
	UserID         identity.UserID
	OrganizationID OrganizationID
	Version        uint64
}

// Owner is an immutable tagged value. Zero is invalid; copies share no mutable
// state. Credential ownership never implies a verified human actor.
type Owner struct{ spec OwnerSpec }

func NewOwner(s OwnerSpec) (Owner, error) {
	if !scope(string(s.TenantID), 128) || s.Version == 0 {
		return Owner{}, ErrInvalid
	}
	switch s.Kind {
	case OwnerUser:
		if !scope(string(s.UserID), 128) || s.OrganizationID != "" {
			return Owner{}, ErrInvalid
		}
	case OwnerOrganization:
		if !scope(string(s.OrganizationID), 128) || s.UserID != "" {
			return Owner{}, ErrInvalid
		}
	default:
		return Owner{}, ErrInvalid
	}
	return Owner{spec: s}, nil
}

func (o Owner) Spec() OwnerSpec { return o.spec }
func (o Owner) Version() uint64 { return o.spec.Version }
func (o Owner) Validate() error { _, err := NewOwner(o.spec); return err }

// SameIdentity ignores the epoch only; tenant, kind and typed ID must all match.
func (o Owner) SameIdentity(other Owner) bool {
	a, b := o.spec, other.spec
	return o.Validate() == nil && other.Validate() == nil && a.TenantID == b.TenantID && a.Kind == b.Kind && a.UserID == b.UserID && a.OrganizationID == b.OrganizationID
}

// Organization archive/delete advances a terminal credential epoch (shared-
// issuer SI-02); accepting a later epoch would resurrect pre-archive keys on
// restore. User owners retain their existing current-policy version semantics.
func (o Owner) admitsEpoch(recorded Owner) bool {
	if o.spec.Kind == OwnerOrganization {
		return o.Version() == recorded.Version()
	}
	return o.Version() >= recorded.Version()
}
func (Owner) Format(s fmt.State, _ rune)   { io.WriteString(s, "apikey.Owner(redacted)") }
func (Owner) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// PermissionReductionDisposition is immutable configuration, never caller
// choice. A narrowing decision cannot silently become a revocation or vice versa.
type PermissionReductionDisposition uint8

const (
	PermissionReductionUnspecified PermissionReductionDisposition = iota
	PermissionReductionNarrow
	PermissionReductionRevoke
)

// ConfigurationState distinguishes issuance from retained verification.
// VerifyOnly is admitted solely for explicitly selected legacy SHA-256;
// Deprecated remains unsupported.
type ConfigurationState uint8

const (
	ConfigurationUnspecified ConfigurationState = iota
	ConfigurationActive
	ConfigurationVerifyOnly
	ConfigurationDeprecated
	ConfigurationDisabled
)

type QuotaPolicy uint8

const (
	QuotaUnspecified QuotaPolicy = iota
	QuotaUnlimited
)

type CachePolicy uint8

const (
	CacheUnspecified CachePolicy = iota
	CacheDisabled
)

// ConfigurationAlgorithm is selected by trusted server configuration, never by
// the presented token. Zero preserves the existing modern HMAC-SHA-256 profile
// and its exact retained JSON/fingerprint representation.
type ConfigurationAlgorithm uint8

const (
	AlgorithmModernHMACSHA256 ConfigurationAlgorithm = iota
	AlgorithmLegacySHA256V1
)

// ConfigurationSpec selects modern HMAC-SHA-256/32-byte idk_ issuance or an
// explicit verify-only historical bare SHA-256 profile.
// Revision identifies immutable behavior; server-owned ID/revision must be
// selected from stored metadata, never inferred from presented secret text.
// Read, clock and decision budgets fit the shared issuer's 30-second bound.
type ConfigurationSpec struct {
	Algorithm                                                          ConfigurationAlgorithm `json:",omitempty"`
	ID                                                                 string
	Revision                                                           uint64
	State                                                              ConfigurationState
	Issuer, Environment, Audience                                      string
	PermissionReduction                                                PermissionReductionDisposition
	MaximumLifetime, MaximumRead, ClockUncertainty, DecisionRaceBudget time.Duration
	Quota                                                              QuotaPolicy
	Cache                                                              CachePolicy
}

// Configuration freezes one explicit profile. Zero and unsupported selections
// deny; construction performs no policy callback, I/O or secret generation.
type Configuration struct{ spec ConfigurationSpec }

// ConfigurationAuthorityBinding is the independent API-key lifecycle dimension
// scoped to tenant plus configuration ID. The identity-platform lifecycle
// contract names this aggregate lifecycle.dimension.api_key. It is not a key's
// credential-security epoch or root version: changing key A advances this
// dimension without rewriting or revoking key B's independent credential root.
// This structural value grants no authority; the native owner must read/fence
// the real aggregate and preserve the earliest original evidence timestamps.
type ConfigurationAuthorityBinding struct {
	TenantID        identity.TenantID
	ConfigurationID string
	Version         uint64
}

// Validate requires the exact expected tenant/configuration and a positive
// full-width epoch. Only mutations reject an exhausted, non-incrementable epoch.
func (b ConfigurationAuthorityBinding) Validate(tenant identity.TenantID, configurationID string) error {
	if !scope(string(tenant), 128) || !scope(configurationID, 128) || b.TenantID != tenant || b.ConfigurationID != configurationID || b.Version == 0 {
		return ErrInvalid
	}
	return nil
}
func (ConfigurationAuthorityBinding) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.ConfigurationAuthorityBinding(redacted)")
}
func (ConfigurationAuthorityBinding) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

func NewConfiguration(s ConfigurationSpec) (Configuration, error) {
	stateValid := s.Algorithm == AlgorithmModernHMACSHA256 && (s.State == ConfigurationActive || s.State == ConfigurationDisabled) || s.Algorithm == AlgorithmLegacySHA256V1 && (s.State == ConfigurationVerifyOnly || s.State == ConfigurationDisabled)
	if !scope(s.ID, 128) || s.Revision == 0 || !stateValid || !scope(s.Issuer, 256) || !scope(s.Environment, 128) || !scope(s.Audience, 256) || s.PermissionReduction < PermissionReductionNarrow || s.PermissionReduction > PermissionReductionRevoke || s.MaximumLifetime <= 0 || s.Algorithm == AlgorithmModernHMACSHA256 && s.MaximumLifetime > 365*24*time.Hour || s.MaximumRead <= 0 || s.MaximumRead > 10*time.Second || s.ClockUncertainty < 0 || s.DecisionRaceBudget < 0 || s.ClockUncertainty > 10*time.Second || s.DecisionRaceBudget > 10*time.Second-s.ClockUncertainty || s.Quota != QuotaUnlimited || s.Cache != CacheDisabled {
		return Configuration{}, ErrInvalid
	}
	return Configuration{spec: s}, nil
}
func (c Configuration) Spec() ConfigurationSpec { return c.spec }
func (c Configuration) Validate() error         { _, err := NewConfiguration(c.spec); return err }
func (c Configuration) AllowsIssuance() bool {
	return c.Validate() == nil && c.spec.State == ConfigurationActive
}
func (c Configuration) AllowsVerification() bool {
	return c.Validate() == nil && c.spec.State != ConfigurationDisabled
}

func scope(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}
