// Package email owns email address policy and lifecycle. Address parsing alone
// does not prove ownership, uniqueness, deliverability or authentication.
package email

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"strings"
	"unicode/utf8"

	identifier "github.com/faustbrian/go-identifier/v2"
)

// ErrInvalidAddress denies an unusable mailbox without including its input.
var ErrInvalidAddress = errors.New("identity.email.invalid_address")

// ErrInvalidPolicy denies absent or incompatible address policy.
var ErrInvalidPolicy = errors.New("identity.email.invalid_policy")

// ErrSensitiveSerialization prevents implicit export of address information.
var ErrSensitiveSerialization = errors.New("identity.email.sensitive_serialization")

// AddressInput is sensitive unnormalized UTF-8 input, at most 4096 bytes.
// Direct conversions are revalidated by Parse. Explicit string conversion
// reveals it; direct formatting/logging redact and serialization fails closed.
// As a raw string scalar, private enclosing fields can bypass these methods;
// never put raw input into diagnostic objects. Parsed Address has opaque custody.
type AddressInput string

// AddressPolicy is copied by NewAddressParser. MaximumBytes bounds input and
// canonical output to 3..4096 bytes; transport bounds remain stricter. The
// explicit Canonicalization profile selects local-part Unicode/case/edge-trim
// policy and must not treat a whole mailbox as an IDNA domain. Domain processing
// separately uses identifier's fixed, nontransitional STD3 IDNA implementation.
// Policy ID/version must change when comparison rules change. PreserveDisplay
// retains the original accepted input, not a mailbox display-name or authority.
type AddressPolicy struct {
	MaximumBytes     uint32
	Canonicalization identifier.NormalizationProfile
	PreserveDisplay  bool
}

// AddressParser freezes address policy and is safe for concurrent use. Zero is
// invalid. It owns no resources, callbacks, DNS queries, goroutines or stores.
type AddressParser struct {
	policy AddressPolicy
	domain identifier.NormalizationProfile
}

// Address is an immutable admitted mailbox, not proof of address ownership.
// Its zero is invalid; Parse is its only construction path. Ordinary diagnostics
// redact. Explicit Canonical and Display projections remain sensitive.
type Address struct{ state *addressState }

// Pointer custody prevents inline disclosure when fmt bypasses Format on a
// consumer's unexported enclosing field. State never changes after Parse.
type addressState struct {
	canonical identifier.Canonical
	display   string
}

// NewAddressParser validates and freezes policy without IO. It accepts only an
// exact mailbox, not names, groups, comments, quoted local parts, domain literals
// or multiple recipients. It deliberately performs no plus-address stripping,
// provider alias rewriting or DNS/deliverability inference. SMTPUTF8 local parts
// may be retained; the selected sender must separately support their delivery.
func NewAddressParser(policy AddressPolicy) (AddressParser, error) {
	if policy.MaximumBytes < 3 || policy.MaximumBytes > 4096 {
		return AddressParser{}, ErrInvalidPolicy
	}
	// A valid mailbox profile must admit the shortest structural mailbox; this
	// also rejects a zero profile or whole-value IDNA policy without inspecting
	// the normalization owner's private configuration.
	if _, err := identifier.Normalize(identifier.Input("x@y"), policy.Canonicalization); err != nil {
		return AddressParser{}, ErrInvalidPolicy
	}
	domain, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "identity.email.domain", Version: 1, Unicode: identifier.UnicodeNormalizationNFC,
		IDNA: true, MaximumBytes: 253,
	})
	if err != nil {
		return AddressParser{}, ErrInvalidPolicy
	}
	return AddressParser{policy: policy, domain: domain}, nil
}

// Parse bounds raw input before normalization or parsing and returns only an
// exact dot-atom mailbox. Local part is at most 64 UTF-8 bytes; the resulting
// mailbox is at most 254 bytes and within MaximumBytes. Domain case and IDN are
// canonicalized by fixed identifier tables, while local-part comparison follows
// the explicitly selected profile. Original controls and malformed UTF-8 always
// deny, even if a selected profile would remove them. Errors never retain input.
// No uniqueness, ownership, delivery or current authority is established.
func (p AddressParser) Parse(input AddressInput) (Address, error) {
	if p.policy.MaximumBytes < 3 || len(input) == 0 || len(input) > int(p.policy.MaximumBytes) || !utf8.ValidString(string(input)) {
		return Address{}, ErrInvalidAddress
	}
	for _, r := range input {
		if r < 32 || r >= 127 && r <= 159 {
			return Address{}, ErrInvalidAddress
		}
	}
	// The comparison profile owns only the local part. Folding the domain
	// first would turn nontransitional IDNs such as faß.de into different DNS
	// destinations. Admit the separator before either component is normalized.
	if strings.Count(string(input), "@") != 1 {
		return Address{}, ErrInvalidAddress
	}
	rawLocal, rawDomain, _ := strings.Cut(string(input), "@")
	normalized, err := identifier.Normalize(identifier.Input(rawLocal), p.policy.Canonicalization)
	if err != nil {
		return Address{}, ErrInvalidAddress
	}
	dns, err := identifier.Normalize(identifier.Input(rawDomain), p.domain)
	if err != nil || strings.HasSuffix(dns.Record().Value, ".") {
		return Address{}, ErrInvalidAddress
	}
	value := normalized.Record().Value + "@" + dns.Record().Value
	// net/mail accepts any multibyte rune as internationalized atom text.
	// This identity profile additionally excludes a fixed set of invisible
	// separators; toolchain Unicode category upgrades cannot reinterpret it.
	for _, r := range value {
		if strings.ContainsRune("\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000", r) {
			return Address{}, ErrInvalidAddress
		}
	}
	if strings.ContainsAny(value, "\"()<>[]\\,:;") || strings.Count(value, "@") != 1 {
		return Address{}, ErrInvalidAddress
	}
	local, _, _ := strings.Cut(value, "@")
	if len(local) == 0 || len(local) > 64 {
		return Address{}, ErrInvalidAddress
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Name != "" || parsed.Address != value {
		return Address{}, ErrInvalidAddress
	}
	if len(value) > 254 || len(value) > int(p.policy.MaximumBytes) {
		return Address{}, ErrInvalidAddress
	}
	// Bind the final comparison record only after the domain is ASCII IDNA.
	// Rechecking the fixed point prevents hidden transformations of that record.
	canonical, err := identifier.Normalize(identifier.Input(value), p.policy.Canonicalization)
	if err != nil || canonical.Record().Value != value {
		return Address{}, ErrInvalidAddress
	}
	s := &addressState{canonical: canonical}
	if p.policy.PreserveDisplay {
		s.display = strings.Clone(string(input))
	}
	return Address{state: s}, nil
}

// Canonical explicitly exposes the complete sensitive comparison identity and
// policy binding. Zero returns an invalid identifier.Canonical. Equality is not
// address ownership or authorization; persistence must enforce scoped uniqueness.
func (a Address) Canonical() identifier.Canonical {
	if a.state == nil {
		return identifier.Canonical{}
	}
	return a.state.canonical
}

// Display explicitly reveals the original accepted input only when enabled.
// Empty means display retention was disabled or the address is invalid. It must
// not be used for lookup, authorization or unescaped rendering.
func (a Address) Display() string {
	if a.state == nil {
		return ""
	}
	return a.state.display
}

// Format redacts unnormalized input for every formatting verb.
func (AddressInput) Format(s fmt.State, _ rune) { io.WriteString(s, "email.AddressInput(redacted)") }

// LogValue redacts input under structured logging.
func (AddressInput) LogValue() slog.Value { return slog.StringValue("email.AddressInput(redacted)") }

// MarshalJSON denies implicit input export; explicit conversion remains sensitive.
func (AddressInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit input export.
func (AddressInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts address projections for every formatting verb.
func (Address) Format(s fmt.State, _ rune) { io.WriteString(s, "email.Address(redacted)") }

// LogValue redacts address projections under structured logging.
func (Address) LogValue() slog.Value { return slog.StringValue("email.Address(redacted)") }

// MarshalJSON denies implicit address export.
func (Address) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit address export.
func (Address) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
