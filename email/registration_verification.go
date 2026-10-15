package email

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidVerification denies malformed or mismatched mailbox verification
// without exposing account existence, address, redirect or capability material.
var ErrInvalidVerification = errors.New("identity.email.invalid_verification")

// CapabilityPayload is email-owned sensitive intent, not a signed grant or
// ownership proof. CanonicalAddress must come from the configured address owner;
// Redirect is the exact startup-allowlisted callback, never a bearer URL. Version
// is the positive token generation, distinct from identifier/verification record
// versions. Explicit field projections remain sensitive. Zero is invalid.
type CapabilityPayload struct {
	TenantID         identity.TenantID
	SubjectID        identity.SubjectID
	CanonicalAddress identifier.Canonical
	Purpose          capability.Purpose
	Redirect         url.URL
	Version          uint64
}

// RegistrationVerificationSpec binds the unchanged anonymous signup origin to
// its separately selected new user and pending email record. It contains no
// session or authentication assertion. Canonical ID admission belongs to the
// originating identity workflow; opaque canonical IDs including ULIDs are
// preserved, not converted to the default generated-ID format. Whole-second
// instants are original issuance history and must never be renewed on retries.
type RegistrationVerificationSpec struct {
	Binding             identity.CommandBinding
	IdentifierID        identity.IdentifierID
	IdentifierVersion   uint64
	VerificationVersion uint64
	Payload             CapabilityPayload
	IssuedAt, ExpiresAt time.Time
}

// RegistrationVerificationConfig is trusted startup policy. The actual address
// policy is frozen by its parser; callbacks are a closed set of 1..32 HTTPS URLs
// (each at most 2048 bytes). MaximumLifetime is explicit, whole-second, positive
// and at most 24h. Dedicated nonzero HMAC keys bind private mailbox intent without
// publishing an unkeyed address index; retain 1..16 versions while original
// grants exist. They must be independent of signing/replay/encryption keys.
// No clocks, stores, providers, sender callbacks or session engines are owned.
type RegistrationVerificationConfig struct {
	Address                  AddressPolicy
	Issuer, Audience         string
	MaximumLifetime          time.Duration
	Redirects                []string
	CurrentBindingKeyVersion uint32
	RetainedBindingKeys      map[uint32][32]byte
}

// RegistrationVerificationPolicy owns the email issuance/authorization shape,
// not signing, scanner-safe validation, consumption or durable mutation. Zero
// denies. Its copied configuration is immutable and concurrent-safe; it owns no
// resources. The public confirmation action is identity.email.verification-confirm;
// identity.identifier.verify remains the internal one-use capability purpose.
type RegistrationVerificationPolicy struct {
	state *registrationVerificationPolicy
}

// Pointer custody prevents private enclosing diagnostic fields from traversing
// retained key maps when Go bypasses the outer value's formatter.
type registrationVerificationPolicy struct {
	parser   AddressParser
	issuer   string
	audience string
	lifetime time.Duration
	current  uint32
	keys     map[uint32][32]byte
	redirect map[string]bool
}

// NewRegistrationVerificationPolicy freezes bounded real policy without IO,
// callbacks, entropy or granting verification authority. It does not reinterpret
// the authenticated-session identifier-management proof profile.
func NewRegistrationVerificationPolicy(c RegistrationVerificationConfig) (*RegistrationVerificationPolicy, error) {
	if len(c.Issuer) > 256 || len(c.Redirects) == 0 || len(c.Redirects) > 32 {
		return nil, ErrInvalidVerification
	}
	for _, raw := range c.Redirects {
		if len(raw) > 2048 {
			return nil, ErrInvalidVerification
		}
	}
	parser, err := NewAddressParser(c.Address)
	u, parseErr := url.Parse(c.Issuer)
	_, issuerValid := verificationURL(u, 256)
	if err != nil || parseErr != nil || !issuerValid || u.RawQuery != "" || u.ForceQuery || !verificationID(c.Audience) || c.MaximumLifetime <= 0 || c.MaximumLifetime > 24*time.Hour || c.MaximumLifetime%time.Second != 0 || c.CurrentBindingKeyVersion == 0 || len(c.RetainedBindingKeys) == 0 || len(c.RetainedBindingKeys) > 16 || c.RetainedBindingKeys[c.CurrentBindingKeyVersion] == ([32]byte{}) {
		return nil, ErrInvalidVerification
	}
	for version, key := range c.RetainedBindingKeys {
		if version == 0 || key == ([32]byte{}) {
			return nil, ErrInvalidVerification
		}
	}
	redirects := make(map[string]bool, len(c.Redirects))
	for _, raw := range c.Redirects {
		u, err := url.Parse(raw)
		rendered, valid := verificationURL(u, 2048)
		if err != nil || !valid || redirects[raw] || rendered != raw {
			return nil, ErrInvalidVerification
		}
		redirects[raw] = true
	}
	return &RegistrationVerificationPolicy{state: &registrationVerificationPolicy{parser: parser, issuer: c.Issuer, audience: c.Audience, lifetime: c.MaximumLifetime, current: c.CurrentBindingKeyVersion, keys: maps.Clone(c.RetainedBindingKeys), redirect: redirects}}, nil
}

func verificationID(value string) bool {
	_, err := identity.ParseIdentifierID(value)
	return err == nil
}

func verificationURL(u *url.URL, maximum int) (string, bool) {
	if u == nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return "", false
	}
	// Bound every raw component, including ignored RawPath, before URL.String
	// can escape or allocate. The fixed component count bounds total work without
	// double-counting decoded Path and its valid encoded RawPath as URL bytes.
	for _, component := range []string{u.Scheme, u.Host, u.Path, u.RawPath, u.RawQuery} {
		if len(component) > maximum {
			return "", false
		}
	}
	if u.Hostname() == "" {
		return "", false
	}
	rendered := u.String()
	if len(rendered) > maximum || strings.Contains(rendered, "#") {
		return "", false
	}
	for _, r := range rendered {
		if r <= 32 || r == 127 {
			return "", false
		}
	}
	// A caller can construct url.URL without Parse's authority checks. Reparse
	// only after bounding rendered bytes, retaining the original representation.
	if _, err := url.Parse(rendered); err != nil {
		return "", false
	}
	return rendered, true
}

func registrationVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
}

// Payload returns fresh caller-owned unsigned capability input with an empty ID:
// the real issuer selects the grant ID. This grants no mailbox ownership, send,
// current authorization or mutation authority. Neither entropy nor signing runs.
// It preserves original whole-second expiry; caller must check live admission
// before handing it to the original journal-owned generation phase.
func (p *RegistrationVerificationPolicy) Payload(s RegistrationVerificationSpec) (capability.Payload, error) {
	if p == nil || p.state == nil {
		return capability.Payload{}, ErrInvalidVerification
	}
	return p.payload(s, p.state.current)
}

func (p *RegistrationVerificationPolicy) payload(s RegistrationVerificationSpec, version uint32) (capability.Payload, error) {
	redirect, valid := verificationURL(&s.Payload.Redirect, 2048)
	if !valid {
		return capability.Payload{}, ErrInvalidVerification
	}
	if p == nil || p.state == nil || p.state.keys[version] == ([32]byte{}) || s.Binding.ValidateFor(registrationVerificationOperation()) != nil || s.Binding.TenantID != s.Payload.TenantID || !verificationID(string(s.Payload.SubjectID)) || !verificationID(string(s.IdentifierID)) || s.IdentifierVersion == 0 || s.IdentifierVersion == math.MaxUint64 || s.VerificationVersion == 0 || s.VerificationVersion == math.MaxUint64 || s.Payload.Version == 0 || s.Payload.Purpose != "identity.identifier.verify" || !p.state.redirect[redirect] || s.IssuedAt.IsZero() || s.IssuedAt.Unix() <= 0 || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || s.ExpiresAt.UTC().Year() > 9999 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > p.state.lifetime {
		return capability.Payload{}, ErrInvalidVerification
	}
	record := s.Payload.CanonicalAddress.Record()
	address, err := p.state.parser.Parse(AddressInput(record.Value))
	if err != nil || !address.Canonical().Equal(s.Payload.CanonicalAddress) {
		return capability.Payload{}, ErrInvalidVerification
	}
	key := p.state.keys[version]
	h := hmac.New(sha256.New, key[:])
	_, _ = io.WriteString(h, "golib.identity.email.registration-verification.v1\x00")
	// Length-framed exact input prevents concatenation collisions. This is a
	// commitment, not normalization, an independent authority or a lookup index.
	for _, value := range []string{string(s.Binding.TenantID), string(s.Payload.SubjectID), string(s.IdentifierID), record.Value, string(record.ProfileID), strconv.FormatUint(uint64(record.ProfileVersion), 10), string(s.Payload.Purpose), redirect, strconv.FormatUint(s.Payload.Version, 10), strconv.FormatUint(s.IdentifierVersion, 10), strconv.FormatUint(s.VerificationVersion, 10), string(s.Binding.CommandID), s.Binding.AnonymousFlowID, string(s.Binding.ActorID), string(s.Binding.ActorKind), string(s.Binding.PolicyID), strconv.FormatUint(s.Binding.PolicyVersion, 10), s.Binding.CorrelationID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, value)
	}
	return capability.Payload{Version: 1, Issuer: p.state.issuer, Audiences: []string{p.state.audience}, Subject: string(s.Payload.SubjectID), Resource: string(s.IdentifierID), Operation: string(s.Payload.Purpose), Tenant: string(s.Payload.TenantID), CorrelationID: s.Binding.CorrelationID, IssuedAt: s.IssuedAt.UTC(), NotBefore: s.IssuedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), MaxUses: 1, Caveats: map[string]string{"email.confirm_operation": "identity.email.verification-confirm", "email.profile": "registration-v1", "email.intent": hex.EncodeToString(h.Sum(nil)), "email.binding_key_version": strconv.FormatUint(uint64(version), 10)}}, nil
}

// Authorize checks an already cryptographically authenticated grant against
// exact original email intent and explicit current time. It does not reverify a
// signature, query revocation/current state, consume, mutate or issue a session.
// Confirmation still owns fresh primary versions, policy and atomic one-use
// effects; scanner-safe use must remain read-only. Retained key versions are
// selected only from the authenticated grant and cannot renew its freshness.
func (p *RegistrationVerificationPolicy) Authorize(grant capability.Grant, s RegistrationVerificationSpec, now time.Time) error {
	g := grant.Payload()
	version, err := strconv.ParseUint(g.Caveats["email.binding_key_version"], 10, 32)
	expected, shapeErr := p.payload(s, uint32(version))
	if err != nil || shapeErr != nil || !verificationID(g.ID) || now.IsZero() || now.Before(g.NotBefore) || !now.Before(g.ExpiresAt) || g.Version != 1 || g.Issuer != expected.Issuer || g.Bearer || g.MaxUses != 1 || len(g.Audiences) != 1 || len(g.Caveats) != len(expected.Caveats) || !g.IssuedAt.Equal(expected.IssuedAt) || !g.NotBefore.Equal(expected.NotBefore) || !g.ExpiresAt.Equal(expected.ExpiresAt) || g.CorrelationID != expected.CorrelationID {
		return ErrInvalidVerification
	}
	if grant.Authorize(capability.Use{Issuer: expected.Issuer, Audience: p.state.audience, Subject: expected.Subject, Resource: expected.Resource, Operation: expected.Operation, Tenant: expected.Tenant, Caveats: expected.Caveats}) != nil {
		return ErrInvalidVerification
	}
	return nil
}

// Format hides mailbox, callback, key material and original correlation.
func (CapabilityPayload) Format(s fmt.State, _ rune) {
	io.WriteString(s, "email.CapabilityPayload(redacted)")
}
func (RegistrationVerificationSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "email.RegistrationVerificationSpec(redacted)")
}
func (RegistrationVerificationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "email.RegistrationVerificationConfig(redacted)")
}
func (RegistrationVerificationPolicy) Format(s fmt.State, _ rune) {
	io.WriteString(s, "email.RegistrationVerificationPolicy(redacted)")
}

// MarshalJSON refuses implicit sensitive-intent projection.
func (CapabilityPayload) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (RegistrationVerificationSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (RegistrationVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (RegistrationVerificationPolicy) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText refuses implicit sensitive text and map-key projection.
func (CapabilityPayload) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (RegistrationVerificationSpec) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (RegistrationVerificationConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (RegistrationVerificationPolicy) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// LogValue hides private intent and cryptographic configuration.
func (CapabilityPayload) LogValue() slog.Value {
	return slog.StringValue("email.CapabilityPayload(redacted)")
}
func (RegistrationVerificationSpec) LogValue() slog.Value {
	return slog.StringValue("email.RegistrationVerificationSpec(redacted)")
}
func (RegistrationVerificationConfig) LogValue() slog.Value {
	return slog.StringValue("email.RegistrationVerificationConfig(redacted)")
}
func (RegistrationVerificationPolicy) LogValue() slog.Value {
	return slog.StringValue("email.RegistrationVerificationPolicy(redacted)")
}
