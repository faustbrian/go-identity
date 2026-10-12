package email

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// MagicLinkPossessionConfig is trusted, explicit startup acceptance of the
// prospective signup-by-link mailbox-possession profile. Version is nonzero and
// must change when acceptance semantics change. Callbacks contains 1..32 exact
// HTTPS URLs, without credentials/fragments, each at most 2048 bytes. Lifetime is
// whole-second, positive and at most 24h. Address policy is the original request's
// canonical comparison policy. This config selects no signer, clock or store.
type MagicLinkPossessionConfig struct {
	Address          AddressPolicy
	Issuer, Audience string
	MaximumLifetime  time.Duration
	Callbacks        []string
	Version          uint64
}

// MagicLinkPossessionSpec is sensitive original request custody, not permission
// to create an account. Native composition reconstructs it from its original
// encrypted creation and authenticated issuance, never from callback overrides.
// IDs and canonical address remain unchanged; creation, browser, selected
// configuration and supersession digests belong to their existing owners.
// IssuedAt/ExpiresAt are the original whole-second UTC instants, not refreshed
// retry times. PolicyVersion must equal the selected email policy's Version.
type MagicLinkPossessionSpec struct {
	TenantID                                           identity.TenantID
	UserID                                             identity.UserID
	IdentifierID                                       identity.IdentifierID
	CanonicalAddress, Callback                         string
	RequestCommandID                                   identity.CommandID
	FlowID                                             string
	FlowBinding, Profile, Supersession, CreationDigest [32]byte
	PolicyVersion                                      uint64
	IssuedAt, ExpiresAt                                time.Time
}

// MagicLinkPossessionPolicy accepts one particular authenticated prospective
// signup grant as mailbox evidence, conditional on its protected consumption
// committing. It does not verify signatures, consume, reserve, mutate, issue a
// session or produce a reusable ownership receipt. Current primary policy,
// collisions, supersession, browser/risk/factor admission and atomic one-use
// remain native workflow responsibilities. Zero denies. Frozen instances are
// concurrent-safe and own no resources or callbacks.
type MagicLinkPossessionPolicy struct{ state *magicLinkPossessionPolicy }

type magicLinkPossessionPolicy struct {
	parser           AddressParser
	issuer, audience string
	lifetime         time.Duration
	version          uint64
	callbacks        map[string]bool
}

// NewMagicLinkPossessionPolicy freezes bounded acceptance configuration without
// IO or granting mailbox ownership. It does not widen password-registration or
// authenticated email-management verification profiles.
func NewMagicLinkPossessionPolicy(c MagicLinkPossessionConfig) (*MagicLinkPossessionPolicy, error) {
	if c.Version == 0 || len(c.Issuer) > 256 || !verificationID(c.Audience) || c.MaximumLifetime <= 0 || c.MaximumLifetime > 24*time.Hour || c.MaximumLifetime%time.Second != 0 || len(c.Callbacks) == 0 || len(c.Callbacks) > 32 {
		return nil, ErrInvalidVerification
	}
	parser, err := NewAddressParser(c.Address)
	u, parseErr := url.Parse(c.Issuer)
	rendered, valid := verificationURL(u, 256)
	if err != nil || parseErr != nil || !valid || rendered != c.Issuer || u.RawQuery != "" || u.ForceQuery {
		return nil, ErrInvalidVerification
	}
	callbacks := make(map[string]bool, len(c.Callbacks))
	for _, raw := range c.Callbacks {
		if len(raw) > 2048 {
			return nil, ErrInvalidVerification
		}
		u, err := url.Parse(raw)
		rendered, valid := verificationURL(u, 2048)
		if err != nil || !valid || rendered != raw || callbacks[raw] {
			return nil, ErrInvalidVerification
		}
		callbacks[raw] = true
	}
	return &MagicLinkPossessionPolicy{state: &magicLinkPossessionPolicy{parser: parser, issuer: c.Issuer, audience: c.Audience, lifetime: c.MaximumLifetime, version: c.Version, callbacks: callbacks}}, nil
}

// Version returns the selected immutable acceptance revision, or zero for an
// unconfigured policy. Derive the native creation policy revision from this
// value, rather than accepting an unrelated caller-supplied number.
func (p *MagicLinkPossessionPolicy) Version() uint64 {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.version
}

// Authorize matches an already cryptographically authenticated grant to the
// complete original prospective intent and explicit current time. Native
// consumption must use its transaction's database time before verified-address
// insertion. Repeated calls are read-only, including scanner inspection; success
// is not a receipt, reservation or permission to bypass native admission.
// Malformed, absent, foreign and expired evidence returns ErrInvalidVerification
// without disclosing mailbox, callback, account existence or bearer material.
func (p *MagicLinkPossessionPolicy) Authorize(grant capability.Grant, s MagicLinkPossessionSpec, now time.Time) error {
	if p == nil || p.state == nil || s.PolicyVersion != p.state.version || !verificationID(string(s.TenantID)) || !verificationID(string(s.UserID)) || !verificationID(string(s.IdentifierID)) || len(s.Callback) > 2048 || !p.state.callbacks[s.Callback] || s.FlowBinding == ([32]byte{}) || s.Profile == ([32]byte{}) || s.Supersession == ([32]byte{}) || s.CreationDigest == ([32]byte{}) || s.IssuedAt.IsZero() || s.IssuedAt.Location() != time.UTC || s.ExpiresAt.Location() != time.UTC || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > p.state.lifetime || now.IsZero() || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) {
		return ErrInvalidVerification
	}
	if _, err := identity.ParseCommandID(string(s.RequestCommandID)); err != nil {
		return ErrInvalidVerification
	}
	if _, err := identity.ParsePreAuthTransactionID(s.FlowID); err != nil {
		return ErrInvalidVerification
	}
	address, err := p.state.parser.Parse(AddressInput(s.CanonicalAddress))
	if err != nil || address.Canonical().Record().Value != s.CanonicalAddress {
		return ErrInvalidVerification
	}
	g := grant.Payload()
	if g.Version != 1 || !verificationID(g.ID) || g.Issuer != p.state.issuer || g.Bearer || g.MaxUses != 1 || len(g.Audiences) != 1 || g.Audiences[0] != p.state.audience || g.CorrelationID != string(s.RequestCommandID) || !g.IssuedAt.Equal(s.IssuedAt) || !g.NotBefore.Equal(s.IssuedAt) || !g.ExpiresAt.Equal(s.ExpiresAt) || len(g.Caveats) != 17 {
		return ErrInvalidVerification
	}
	caveats := map[string]string{
		"magiclink.identifier":         string(s.IdentifierID),
		"magiclink.identifier-version": "1", "magiclink.verification-version": "1",
		"magiclink.identifier-authority-version": "1", "magiclink.user-authority-version": "1",
		"magiclink.credential-authority-version": "1", "magiclink.factor-version": "1",
		"magiclink.canonical-email": s.CanonicalAddress, "magiclink.callback": s.Callback,
		"magiclink.intent": "signup-if-allowed", "magiclink.prospective": "1",
		"magiclink.flow": s.FlowID, "magiclink.flow-binding": hex.EncodeToString(s.FlowBinding[:]),
		"magiclink.profile": hex.EncodeToString(s.Profile[:]), "magiclink.supersession": hex.EncodeToString(s.Supersession[:]),
		"magiclink.creation-digest":      hex.EncodeToString(s.CreationDigest[:]),
		"magiclink.email-policy-version": strconv.FormatUint(s.PolicyVersion, 10),
	}
	if grant.Authorize(capability.Use{Audience: p.state.audience, Subject: string(s.UserID), Tenant: string(s.TenantID), Resource: "identity.magiclink/" + string(s.IdentifierID), Operation: "identity.magic-link.consume", Caveats: caveats}) != nil {
		return ErrInvalidVerification
	}
	return nil
}

// Format redacts startup callbacks and policy metadata.
func (MagicLinkPossessionConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.MagicLinkPossessionConfig(redacted)")
}

// MarshalJSON rejects implicit configuration export.
func (MagicLinkPossessionConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit textual configuration export.
func (MagicLinkPossessionConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured configuration diagnostics.
func (MagicLinkPossessionConfig) LogValue() slog.Value {
	return slog.StringValue("email.MagicLinkPossessionConfig(redacted)")
}

// Format hides original mailbox, browser and creation custody.
func (MagicLinkPossessionSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.MagicLinkPossessionSpec(redacted)")
}

// MarshalJSON rejects implicit original-intent export.
func (MagicLinkPossessionSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit textual original-intent export.
func (MagicLinkPossessionSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured original-intent diagnostics.
func (MagicLinkPossessionSpec) LogValue() slog.Value {
	return slog.StringValue("email.MagicLinkPossessionSpec(redacted)")
}

// Format hides private selected-policy custody.
func (MagicLinkPossessionPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.MagicLinkPossessionPolicy(redacted)")
}

// MarshalJSON rejects implicit selected-policy export.
func (MagicLinkPossessionPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit textual selected-policy export.
func (MagicLinkPossessionPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured selected-policy diagnostics.
func (MagicLinkPossessionPolicy) LogValue() slog.Value {
	return slog.StringValue("email.MagicLinkPossessionPolicy(redacted)")
}
