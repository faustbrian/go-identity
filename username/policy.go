// Package username defines the fixed Latin-v1 username syntax and enrollment
// policy. It owns neither reservation nor authentication; callers must enforce
// uniqueness atomically using canonical bytes and the complete profile binding.
package username

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-identifier/v2"
)

const (
	// ProfileID identifies the immutable Latin-v1 canonicalization contract.
	ProfileID identifier.NormalizationProfileID = "identity.username.latin-v1"
	// ProfileVersion must accompany canonical bytes in persistence and lookup.
	ProfileVersion uint32 = 1
	// UnicodeVersion is independent of the compiler's Unicode database.
	UnicodeVersion = "15.1.0"
	// MinimumCodepoints applies to both supplied display and normalized value.
	MinimumCodepoints = 3
	// MaximumCodepoints applies before and after folding, including expansions.
	MaximumCodepoints = 32
	// MaximumBytes bounds UTF-8 input before normalization and the final result.
	MaximumBytes = 128
)

// Error is a stable, comparable domain error; errors never contain input,
// callback errors, panic values, or account-existence information.
type Error string

const (
	// ErrPolicy denotes invalid or missing startup configuration.
	ErrPolicy Error = "username policy invalid"
	// ErrInvalid denotes invalid encoding, syntax, length, or persistence data.
	ErrInvalid Error = "username invalid"
	// ErrReserved denies enrollment under the selected reserved-name set.
	ErrReserved Error = "username reserved"
	// ErrValidation denies enrollment after a custom error or panic.
	ErrValidation Error = "username validation denied"
	// ErrCanceled denies work after context cancellation or deadline expiry.
	ErrCanceled Error = "username canceled"
	// ErrDisclosure refuses implicit serialization of an opaque name.
	ErrDisclosure Error = "username explicit projection required"
	// ErrUnavailable denies discovery when required native authority is unavailable.
	ErrUnavailable Error = "username unavailable"
	// ErrThrottled denies this attempt after the configured durable rate limit.
	ErrThrottled Error = "username rate limit exceeded"
	// ErrDenied denies a selected risk policy without disclosing provider facts.
	ErrDenied Error = "username denied"
)

// Error returns the stable diagnostic, never sensitive caller input.
func (e Error) Error() string { return string(e) }

// ReservedNames is an explicit startup manifest. Names must be unique canonical
// syntax-valid names of 1..32 codepoints (the reference includes two-letter me).
// SHA256 is lowercase hex over decimal Version + LF followed by sorted names,
// each with LF. Version 1 is the exact reference set, not a customizable alias.
type ReservedNames struct {
	Version uint32
	SHA256  string
	Names   []string
}

// Validator is an enrollment-only decision over an already canonicalized name.
// It receives a deadline-bounded context and must cooperate with cancellation.
// Calls are synchronous, in order, without locks or spawned goroutines; timeout
// cannot preempt an uncooperative callback. Errors and panics deny without being
// returned or logged. Implementations must be safe for concurrent policy use.
type Validator func(context.Context, Name) error

// PolicySpec is copied at startup. ValidationTimeout is positive and at most
// 30 seconds; the earlier caller deadline wins. At most 16 validators and 256
// reserved names are accepted. Syntax and normalization are deliberately fixed.
type PolicySpec struct {
	Reserved          ReservedNames
	Validators        []Validator
	ValidationTimeout time.Duration
}

// Policy is immutable and safe for concurrent use, provided supplied validators
// are also safe. A nil or zero Policy denies work. Reserved/custom decisions
// apply only to Validate, never lookup Canonicalize or restoration.
type Policy struct {
	profile          identifier.NormalizationProfile
	reserved         map[string]struct{}
	reservedVersion  uint32
	reservedChecksum string
	validators       []Validator
	timeout          time.Duration
}

// ReferencePolicySpec returns a fresh manifest for the exact reference v1 set
// and a one-second cooperative callback budget. Callers must pass configuration
// explicitly to NewPolicy; there is no implicit global policy.
func ReferencePolicySpec() PolicySpec {
	names := []string{"admin", "administrator", "api", "auth", "login", "logout", "me", "oauth", "oidc", "root", "scim", "sso", "support", "system", "webhook"}
	return PolicySpec{Reserved: ReservedNames{Version: 1, SHA256: reservedDigest(1, names), Names: names}, ValidationTimeout: time.Second}
}

// NewPolicy validates the explicit version/checksum and copies owned slices.
// Reference reserved version 1 cannot be redefined. Later versions may replace
// the enrollment set without reinterpreting existing canonical identifiers.
func NewPolicy(spec PolicySpec) (*Policy, error) {
	if spec.Reserved.Version == 0 || len(spec.Reserved.Names) == 0 || len(spec.Reserved.Names) > 256 || spec.ValidationTimeout <= 0 || spec.ValidationTimeout > 30*time.Second || len(spec.Validators) > 16 {
		return nil, ErrPolicy
	}
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: ProfileID, Version: ProfileVersion, Unicode: identifier.UnicodeNormalizationNFC, CaseFold: true, MaximumBytes: MaximumBytes})
	if err != nil {
		return nil, ErrPolicy
	}
	names := append([]string(nil), spec.Reserved.Names...)
	seen := make(map[string]struct{}, len(names))
	for i, raw := range names {
		if !validSyntax(raw, 1) {
			return nil, ErrPolicy
		}
		n, normalizeErr := identifier.Normalize(identifier.Input(raw), profile)
		if normalizeErr != nil || n.Record().Value != raw {
			return nil, ErrPolicy
		}
		if _, exists := seen[raw]; exists {
			return nil, ErrPolicy
		}
		names[i] = strings.Clone(raw)
		seen[names[i]] = struct{}{}
	}
	sort.Strings(names)
	digest := reservedDigest(spec.Reserved.Version, names)
	if spec.Reserved.SHA256 != digest || spec.Reserved.Version == 1 && digest != ReferencePolicySpec().Reserved.SHA256 {
		return nil, ErrPolicy
	}
	validators := append([]Validator(nil), spec.Validators...)
	for _, validate := range validators {
		if validate == nil {
			return nil, ErrPolicy
		}
	}
	return &Policy{profile: profile, reserved: seen, reservedVersion: spec.Reserved.Version, reservedChecksum: digest, validators: validators, timeout: spec.ValidationTimeout}, nil
}

// Profile returns the exact fixed normalization profile for persistence wiring.
// A nil or zero Policy returns an invalid zero profile.
func (p *Policy) Profile() identifier.NormalizationProfile {
	if p == nil {
		return identifier.NormalizationProfile{}
	}
	return p.profile
}

// ReservedVersion identifies the enrollment-only startup set, or zero if unset.
func (p *Policy) ReservedVersion() uint32 {
	if p == nil {
		return 0
	}
	return p.reservedVersion
}

// ReservedChecksum returns the validated startup manifest digest, or empty.
func (p *Policy) ReservedChecksum() string {
	if p == nil {
		return ""
	}
	return p.reservedChecksum
}

// Canonicalize performs bounded UTF-8/syntax checks, fixed Unicode 15.1 NFC,
// full non-Turkic fold, and NFC again. Input is never trimmed. Both input and
// output obey 3..32 codepoints and 128 bytes. Lookup deliberately ignores
// enrollment reserved/custom decisions so policy changes cannot strand names.
func (p *Policy) Canonicalize(ctx context.Context, raw string) (Name, error) {
	if p == nil || p.reservedVersion == 0 {
		return Name{}, ErrPolicy
	}
	if ctx == nil {
		return Name{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Name{}, ErrCanceled
	}
	if !validSyntax(raw, MinimumCodepoints) {
		return Name{}, ErrInvalid
	}
	canonical, err := identifier.Normalize(identifier.Input(raw), p.profile)
	if err != nil || !validSyntax(canonical.Record().Value, MinimumCodepoints) {
		return Name{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Name{}, ErrCanceled
	}
	return Name{state: &nameState{canonical: canonical, display: strings.Clone(raw)}}, nil
}

// Validate canonicalizes once and additionally applies reserved/custom
// enrollment decisions for signup/rename. It does not reserve a name or prove
// availability. A denial always returns a zero Name, never a partial value.
func (p *Policy) Validate(ctx context.Context, raw string) (Name, error) {
	n, err := p.Canonicalize(ctx, raw)
	if err != nil {
		return Name{}, err
	}
	if _, reserved := p.reserved[n.state.canonical.Record().Value]; reserved {
		return Name{}, ErrReserved
	}
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	for _, validate := range p.validators {
		if bounded.Err() != nil {
			return Name{}, ErrCanceled
		}
		allowed := runValidator(bounded, validate, n)
		if bounded.Err() != nil {
			return Name{}, ErrCanceled
		}
		if !allowed {
			return Name{}, ErrValidation
		}
	}
	if bounded.Err() != nil {
		return Name{}, ErrCanceled
	}
	return n, nil
}

func runValidator(ctx context.Context, validate Validator, n Name) (allowed bool) {
	defer func() {
		if recover() != nil {
			allowed = false
		}
	}()
	return validate(ctx, n) == nil
}

func reservedDigest(version uint32, names []string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(strconv.FormatUint(uint64(version), 10) + "\n"))
	for _, name := range names {
		_, _ = hash.Write([]byte(name + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validSyntax(text string, minimum int) bool {
	if len(text) > MaximumBytes || !utf8.ValidString(text) {
		return false
	}
	count, latinBase := 0, false
	for _, r := range text {
		count++
		if count > MaximumCodepoints {
			return false
		}
		switch {
		case latinLetter(r):
			latinBase = true
		case r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-':
			latinBase = false
		// Basic inherited diacritics follow a Latin base only. U+034F is
		// Default_Ignorable_Code_Point (Unicode 15.1 DerivedCoreProperties),
		// not a visible accent; admitting it creates invisible distinctions.
		case r >= 0x0300 && r <= 0x036f && r != 0x034f && latinBase:
		default:
			return false
		}
	}
	return count >= minimum
}
