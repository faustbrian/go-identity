// Package phone owns explicitly profiled phone identifiers. Structural validity
// establishes neither ownership nor verification, deliverability or authority.
package phone

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/nyaruka/phonenumbers/v2"
	"github.com/nyaruka/phonenumbers/v2/metadata"
)

// NumberError is a stable redacted number-policy diagnostic.
type NumberError string

// Error returns a fixed diagnostic without caller input or upstream errors.
func (e NumberError) Error() string { return string(e) }

const (
	// ErrNumberPolicy denies missing or unsupported explicit configuration.
	ErrNumberPolicy NumberError = "identity.phone.number_policy"
	// ErrNumberInvalid denies syntax, metadata validity or persistence mismatch.
	ErrNumberInvalid NumberError = "identity.phone.number_invalid"
	// ErrNumberCanceled denies canceled work without returning a partial number.
	ErrNumberCanceled NumberError = "identity.phone.number_canceled"
	// ErrNumberDisclosure requires an explicit sensitive projection.
	ErrNumberDisclosure NumberError = "identity.phone.number_explicit_projection_required"
)

// NumberProfile is the immutable comparison and metadata binding. Persist every
// field with E.164 bytes; changing metadata never upgrades an existing record.
// ID itself includes the metadata revision, so native identifier owners storing
// normalization ID/version retain its binding without private concatenation.
type NumberProfile struct {
	ID              string
	Version         uint32
	MetadataVersion string
}

// CurrentNumberProfile returns the only supported explicit comparison profile.
func CurrentNumberProfile() NumberProfile {
	return NumberProfile{ID: "identity.phone.e164-ascii-v1.metadata-v9.0.40", Version: 1, MetadataVersion: "v9.0.40"}
}

// NumberPolicySpec selects bounded strict ASCII dial strings. MaximumInputBytes
// must be 16..128. National input requires AllowNational and a supported uppercase
// two-letter DefaultRegion; otherwise DefaultRegion must be empty. International
// input never inherits it. PreserveDisplay explicitly retains accepted raw input.
type NumberPolicySpec struct {
	Profile           NumberProfile
	MaximumInputBytes uint32
	AllowNational     bool
	DefaultRegion     string
	PreserveDisplay   bool
}

// NumberPolicy is immutable and safe for concurrent use. Nil and zero policies
// deny. It owns no callbacks, goroutines, services or mutable upstream numbers.
// Applications must not replace/mutate the upstream process-global metadata;
// its override APIs are outside this profile's supported process contract.
type NumberPolicy struct{ spec NumberPolicySpec }

// Number is an immutable opaque identifier; zero is invalid. Explicit Record
// and DeliveryNumber cross a sensitive boundary. Equality is not authority.
type Number struct{ state func() numberState }

// Closure custody avoids fmt traversing sensitive data when an unexported
// enclosing field bypasses Number.Format. Even pointer-backed structs can be
// dereferenced by fmt's bad-verb diagnostics. This private closure captures an
// immutable value; it is not a caller callback or a shared registry.
type numberState struct {
	e164           string
	profile        NumberProfile
	display        string
	nationalRegion string
}

// NumberRecord is the intentionally sensitive persistence projection. Its fields
// are untrusted on load: use Restore. NationalRegion is retained only alongside
// a national Display, never inferred from an international identifier.
type NumberRecord struct {
	E164           string
	Profile        NumberProfile
	Display        string
	NationalRegion string
}

// NewNumberPolicy validates explicit configuration without external IO.
func NewNumberPolicy(spec NumberPolicySpec) (*NumberPolicy, error) {
	if spec.Profile != CurrentNumberProfile() || metadata.Version != spec.Profile.MetadataVersion || spec.MaximumInputBytes < 16 || spec.MaximumInputBytes > 128 {
		return nil, ErrNumberPolicy
	}
	if spec.AllowNational {
		if len(spec.DefaultRegion) != 2 || spec.DefaultRegion[0] < 'A' || spec.DefaultRegion[0] > 'Z' || spec.DefaultRegion[1] < 'A' || spec.DefaultRegion[1] > 'Z' || phonenumbers.GetCountryCodeForRegion(spec.DefaultRegion) == 0 {
			return nil, ErrNumberPolicy
		}
	} else if spec.DefaultRegion != "" {
		return nil, ErrNumberPolicy
	}
	return &NumberPolicy{spec: spec}, nil
}

// Profile returns the frozen profile, or zero for an invalid policy.
func (p *NumberPolicy) Profile() NumberProfile {
	if p == nil || p.spec.Profile != CurrentNumberProfile() {
		return NumberProfile{}
	}
	return p.spec.Profile
}

// Canonicalize accepts strict ASCII international E.164 or, when explicitly
// enabled, the exact digit-only national dial form. It never trims, translates
// Unicode, extracts embedded numbers, expands vanity text or accepts extensions.
func (p *NumberPolicy) Canonicalize(ctx context.Context, raw string) (Number, error) {
	if p == nil || p.spec.Profile != CurrentNumberProfile() {
		return Number{}, ErrNumberPolicy
	}
	if ctx == nil {
		return Number{}, ErrNumberInvalid
	}
	if ctx.Err() != nil {
		return Number{}, ErrNumberCanceled
	}
	if len(raw) == 0 || len(raw) > int(p.spec.MaximumInputBytes) {
		return Number{}, ErrNumberInvalid
	}
	international := raw[0] == '+'
	digits := raw
	region := ""
	if international {
		digits = raw[1:]
		if len(digits) == 0 || len(digits) > 15 || digits[0] == '0' {
			return Number{}, ErrNumberInvalid
		}
	} else {
		if !p.spec.AllowNational {
			return Number{}, ErrNumberInvalid
		}
		region = p.spec.DefaultRegion
	}
	for i := range digits {
		if digits[i] < '0' || digits[i] > '9' {
			return Number{}, ErrNumberInvalid
		}
	}
	// ParseAndKeepRawInput's CountryCodeSource distinguishes real national input
	// from the upstream parser's documented IDD/missing-plus country-code inference
	// (phonenumberutil.go, MaybeExtractCountryCode). Never accept that inference
	// as an identity. The temporary upstream object never escapes this call.
	parsed, err := phonenumbers.ParseAndKeepRawInput(raw, region)
	if err != nil || parsed.GetExtension() != "" || !phonenumbers.IsValidNumber(parsed) || phonenumbers.IsValidShortNumber(parsed) {
		return Number{}, ErrNumberInvalid
	}
	e164 := phonenumbers.Format(parsed, phonenumbers.E164)
	if !canonicalSyntax(e164) {
		return Number{}, ErrNumberInvalid
	}
	if international {
		// Exact fixed point also rejects upstream trunk-prefix repair, e.g. +440...
		// The ASCII-v1 profile does not silently discard caller-supplied digits.
		if parsed.GetCountryCodeSource() != phonenumbers.PhoneNumber_FROM_NUMBER_WITH_PLUS_SIGN || e164 != raw {
			return Number{}, ErrNumberInvalid
		}
	} else if parsed.GetCountryCodeSource() != phonenumbers.PhoneNumber_FROM_DEFAULT_COUNTRY || !phonenumbers.IsValidNumberForRegion(parsed, region) || nationalDigits(parsed) != raw {
		return Number{}, ErrNumberInvalid
	}
	if ctx.Err() != nil {
		return Number{}, ErrNumberCanceled
	}
	s := numberState{e164: e164, profile: p.spec.Profile}
	if p.spec.PreserveDisplay {
		s.display = strings.Clone(raw)
		s.nationalRegion = region
	}
	return newNumber(s), nil
}

// Restore validates original profile, exact canonical E.164 and any retained
// display/region. It never migrates metadata or creates verification facts.
func (p *NumberPolicy) Restore(ctx context.Context, record NumberRecord) (Number, error) {
	if p == nil || p.spec.Profile != CurrentNumberProfile() {
		return Number{}, ErrNumberPolicy
	}
	if record.Profile != p.spec.Profile || !canonicalSyntax(record.E164) {
		return Number{}, ErrNumberInvalid
	}
	canonical, err := p.Canonicalize(ctx, record.E164)
	if err != nil {
		return Number{}, err
	}
	if record.Display == "" {
		if record.NationalRegion != "" {
			return Number{}, ErrNumberInvalid
		}
		// A record without display stays without display even when today's policy
		// permits retention: restoration cannot invent an original input.
		return newNumber(numberState{e164: canonical.state().e164, profile: record.Profile}), nil
	}
	if !p.spec.PreserveDisplay {
		return Number{}, ErrNumberInvalid
	}
	n, err := p.Canonicalize(ctx, record.Display)
	if err != nil {
		return Number{}, err
	}
	if n.state().e164 != record.E164 || n.state().nationalRegion != record.NationalRegion {
		return Number{}, ErrNumberInvalid
	}
	return n, nil
}

// Equal compares E.164 and exact comparison/metadata profile, ignoring display.
// Invalid zero values never compare equal, including to one another.
func (n Number) Equal(other Number) bool {
	return n.state != nil && other.state != nil && n.state().e164 == other.state().e164 && n.state().profile == other.state().profile
}

// DeliveryNumber explicitly exposes sensitive E.164; zero returns an error,
// never a usable empty destination. This does not establish SMS deliverability.
func (n Number) DeliveryNumber() (string, error) {
	if n.state == nil {
		return "", ErrNumberInvalid
	}
	return n.state().e164, nil
}

// Record explicitly exposes sensitive persistence fields; zero returns an error.
func (n Number) Record() (NumberRecord, error) {
	if n.state == nil {
		return NumberRecord{}, ErrNumberInvalid
	}
	s := n.state()
	return NumberRecord{E164: s.e164, Profile: s.profile, Display: s.display, NationalRegion: s.nationalRegion}, nil
}

// Display explicitly reveals retained raw input, or empty when disabled/invalid.
// It must not be used for comparison, authorization or unescaped rendering.
func (n Number) Display() string {
	if n.state == nil {
		return ""
	}
	return n.state().display
}

func newNumber(state numberState) Number {
	return Number{state: func() numberState { return state }}
}

// Format redacts every formatting verb, including Go-syntax and quoted output.
func (Number) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "phone.Number(redacted)") }

// LogValue redacts structured diagnostics, not explicitly projected fields.
func (Number) LogValue() slog.Value { return slog.StringValue("phone.Number(redacted)") }

// MarshalJSON refuses implicit disclosure; project Record explicitly instead.
func (Number) MarshalJSON() ([]byte, error) { return nil, ErrNumberDisclosure }

// MarshalText refuses implicit disclosure.
func (Number) MarshalText() ([]byte, error) { return nil, ErrNumberDisclosure }

// Format redacts the record; separately accessed exported fields are sensitive.
func (NumberRecord) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "phone.NumberRecord(redacted)")
}

// LogValue redacts the record, not separately logged record fields.
func (NumberRecord) LogValue() slog.Value { return slog.StringValue("phone.NumberRecord(redacted)") }

func canonicalSyntax(raw string) bool {
	if len(raw) < 2 || len(raw) > 16 || raw[0] != '+' || raw[1] == '0' {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

func nationalDigits(number *phonenumbers.PhoneNumber) string {
	formatted := phonenumbers.Format(number, phonenumbers.NATIONAL)
	var digits strings.Builder
	for i := range formatted {
		if formatted[i] >= '0' && formatted[i] <= '9' {
			digits.WriteByte(formatted[i])
		}
	}
	return digits.String()
}
