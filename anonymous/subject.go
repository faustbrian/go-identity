// Package anonymous owns anonymous lifecycle policy and subject metadata.
// Kernel identities, credentials, sessions and transactions retain their owners.
package anonymous

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"golang.org/x/text/unicode/norm"
)

// Error is a stable redacted classification with no input or secret payload.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidInput Error = "identity.anonymous.invalid_input"
	ErrInactive     Error = "identity.anonymous.inactive"
	ErrDisclosure   Error = "identity.anonymous.disclosure_forbidden"
)

// CleanupPolicy selects disposal of anonymous-owned state after linking or
// abandonment. Zero/unknown denies. This is not permission to erase kernel,
// session, application or legally retained state: their actual owners and
// current legal-hold policy must separately authorize the protected transition.
type CleanupPolicy uint8

const (
	CleanupDelete CleanupPolicy = iota + 1
	CleanupAnonymize
	CleanupRetain
)

func (p CleanupPolicy) valid() bool { return p >= CleanupDelete && p <= CleanupRetain }

// Config is explicit trusted composition, never request-selected policy. Names
// are NFC-normalized display only, not identifiers. PlaceholderEmailDomain must
// be exactly anonymous.invalid; there is no deliverable/verified-email profile.
// TTL is an absolute 15-minute..30-day lifetime from authoritative creation,
// in whole microseconds so persistence preserves the exact original expiry.
// The core has no defaults; the reference explicitly selects Guest and 24 hours.
type Config struct {
	DisplayName, PlaceholderEmailDomain string
	TTL                                 time.Duration
	Cleanup                             CleanupPolicy
}

// Policy owns immutable validated configuration without IO/resources, clocks or
// mutable global state. Zero denies. Copies are safe for concurrent reads.
type Policy struct{ read func() Config }

// NewPolicy bounds input before normalization and freezes explicit policy. It
// performs no lookup, identity creation, risk evaluation or privilege admission.
func NewPolicy(c Config) (Policy, error) {
	if c.PlaceholderEmailDomain != "anonymous.invalid" || c.TTL < 15*time.Minute || c.TTL > 30*24*time.Hour || c.TTL%time.Microsecond != 0 || !c.Cleanup.valid() || len(c.DisplayName) == 0 || len(c.DisplayName) > 256 || !utf8.ValidString(c.DisplayName) {
		return Policy{}, ErrInvalidInput
	}
	c.DisplayName = norm.NFC.String(c.DisplayName)
	if len(c.DisplayName) > 256 || utf8.RuneCountInString(c.DisplayName) > 64 || strings.TrimSpace(c.DisplayName) == "" {
		return Policy{}, ErrInvalidInput
	}
	for _, r := range c.DisplayName {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return Policy{}, ErrInvalidInput
		}
	}
	c.DisplayName, c.PlaceholderEmailDomain = strings.Clone(c.DisplayName), strings.Clone(c.PlaceholderEmailDomain)
	return Policy{read: func() Config { return c }}, nil
}

// Config explicitly projects the frozen non-authoritative policy. It does not
// renew TTL or prove installed owner histories, current state or risk admission.
func (p Policy) Config() (Config, error) {
	if p.read == nil {
		return Config{}, ErrInvalidInput
	}
	return p.read(), nil
}

// State is the closed anonymous lifecycle. Terminal states preserve historical
// identity/version; expiry alone never makes another state active again.
type State uint8

const (
	StateActive State = iota + 1
	StateUpgraded
	StateDeleted
	StateExpired
	StateAnonymized
	StateRetained
)

// SubjectSpec is sensitive explicit persistence/inspection input. The selected
// profile binds the opaque anonymous ID to its kernel UserID, not a contact or
// caller-selected permanent identity. CreatedAt/ExpiresAt are original primary
// database instants with microsecond precision; no later read may replace them.
// Version belongs to anonymous state, separately from kernel/session epochs.
// No ordinary user attributes, bearer, credential or application data are copied.
type SubjectSpec struct {
	ID                   identity.SubjectID
	TenantID             identity.TenantID
	UserID               identity.UserID
	CreatedAt, ExpiresAt time.Time
	State                State
	Version              uint64
	Cleanup              CleanupPolicy
}

// AnonymousSubject owns an immutable original lifecycle projection. Construction
// and Record confer no possession, current authority or right to upgrade. Zero
// denies; copies retain exact state/expiry and support concurrent reads.
type AnonymousSubject struct{ read func() SubjectSpec }

// NewAnonymousSubject validates and freezes owner-supplied structural metadata.
// Historical terminal states remain inspectable, not authenticated/reactivated.
func NewAnonymousSubject(s SubjectSpec) (AnonymousSubject, error) {
	if _, err := identity.ParseSubjectID(string(s.ID)); err != nil {
		return AnonymousSubject{}, ErrInvalidInput
	}
	user := identity.User{ID: s.UserID, TenantID: s.TenantID, Status: identity.StatusActive, Version: 1}
	if string(s.ID) != string(s.UserID) || user.Validate(s.TenantID) != nil || !subjectTime(s.CreatedAt) || !subjectTime(s.ExpiresAt) || s.ExpiresAt.Sub(s.CreatedAt) < 15*time.Minute || s.ExpiresAt.Sub(s.CreatedAt) > 30*24*time.Hour || s.State < StateActive || s.State > StateRetained || s.Version == 0 || s.State != StateActive && s.Version == 1 || !s.Cleanup.valid() {
		return AnonymousSubject{}, ErrInvalidInput
	}
	s.CreatedAt, s.ExpiresAt = s.CreatedAt.UTC(), s.ExpiresAt.UTC()
	return AnonymousSubject{read: func() SubjectSpec { return s }}, nil
}

func subjectTime(t time.Time) bool {
	return validInstant(t) && t.Truncate(time.Microsecond).Equal(t)
}

func validInstant(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

// Record explicitly projects sensitive historical metadata. It neither reads
// primary state nor grants authorization; never log or serialize its fields.
func (s AnonymousSubject) Record() (SubjectSpec, error) {
	if s.read == nil {
		return SubjectSpec{}, ErrInvalidInput
	}
	return s.read(), nil
}

// RequireActive checks the retained exact tenant/state and exclusive original
// lifetime at trusted now. It grants no renewable validity, session admission,
// mutation permission or protection against a later primary state transition.
func (s AnonymousSubject) RequireActive(tenant identity.TenantID, now time.Time) error {
	r, err := s.Record()
	if err != nil {
		return err
	}
	if r.TenantID != tenant || !validInstant(now) || now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt) || r.State != StateActive {
		return ErrInactive
	}
	return nil
}

// RequireExpired checks only an active lifecycle's exact tenant and exclusive
// original expiry at trusted now. Maintenance must supply authoritative database
// time and separately authorize/fence the protected cleanup with all owners.
// This grants no service, session or erasure authority; terminal states, including
// an already expired/disposed lifecycle, are never candidates for another change.
func (s AnonymousSubject) RequireExpired(tenant identity.TenantID, now time.Time) error {
	r, err := s.Record()
	if err != nil {
		return err
	}
	if r.TenantID != tenant || !validInstant(now) || now.Before(r.ExpiresAt) || r.State != StateActive {
		return ErrInactive
	}
	return nil
}

func (Policy) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("anonymous.Policy(redacted)")) }
func (Policy) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (Policy) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (Policy) LogValue() slog.Value         { return slog.StringValue("anonymous.Policy(redacted)") }
func (AnonymousSubject) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.AnonymousSubject(redacted)"))
}
func (AnonymousSubject) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (AnonymousSubject) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (AnonymousSubject) LogValue() slog.Value {
	return slog.StringValue("anonymous.AnonymousSubject(redacted)")
}
func (SubjectSpec) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.SubjectSpec(redacted)"))
}
func (SubjectSpec) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SubjectSpec) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
