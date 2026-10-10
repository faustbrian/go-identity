package identity

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	primitive "github.com/faustbrian/go-password"
)

// FeatureKind selects exactly one named command scalar. Zero/unknown kinds are
// invalid; inactive members must be exactly zero (including nil Bytes).
type FeatureKind uint8

const (
	// FeatureText selects bounded UTF-8 text without implicit normalization.
	FeatureText FeatureKind = iota + 1
	// FeatureBytes selects bounded binary metadata, never a raw bearer/secret.
	FeatureBytes
	// FeatureUint64 preserves the complete unsigned authority-version range.
	FeatureUint64
	// FeatureInt64 selects a signed integer (including duration microseconds).
	FeatureInt64
	// FeatureBool selects an explicit boolean, including false.
	FeatureBool
	// FeatureTime selects a nonzero microsecond-exact year 1..9999 UTC instant.
	FeatureTime
)

// FeatureValue is a closed scalar union for trusted feature command mapping.
// Kind is required even for empty text/bytes, false or zero integers. Text/Bytes
// are at most 8192 bytes; text must be valid UTF-8. Time is normalized to UTC
// without changing its instant. Values are command input, not authentication or
// an authority proof. Never place raw passwords, session/API-key bearers, private
// keys or provider tokens here. Feature owners define and validate exact field
// semantics, including confidentiality and cryptographic evidence provenance.
type FeatureValue struct {
	Kind   FeatureKind
	Text   string
	Bytes  []byte
	Uint64 uint64
	Int64  int64
	Bool   bool
	Time   time.Time
}

// FeatureField is one named typed input, not an extension hook or arbitrary
// serialized blob. Name is at most 128 lowercase ASCII bytes in dot-separated
// segments with the FeatureOperation.OperationID syntax. Duplicate names deny.
// Named field order has no meaning; owners explicitly encode sequence indexes
// in field names when their schema needs ordered inputs. All behavior-affecting
// input, including expected versions and options, must be mapped exhaustively.
type FeatureField struct {
	Name  string
	Value FeatureValue
}

// FeatureCommandSpec is a structural, storage-neutral trusted mapping input.
// Binding must match Operation exactly. Fields contains 0..128 distinct named
// scalars and at most 256 KiB counted as each name's byte length, one kind byte
// and value bytes (integers/time count eight, booleans one). There are no floats,
// executable callbacks, raw JSON/CBOR, transaction handles or arbitrary values.
// This public projection is not a secret-custody boundary: never log/serialize
// it or use it for HTTP responses. The returned opaque Command supplies the
// diagnostic boundary. Do not mutate inputs concurrently with construction.
// Feature services still own their native typed commands. Trusted adapters alone
// map these to this shared vocabulary; applications need no workflow glue.
type FeatureCommandSpec struct {
	Binding   CommandBinding
	Operation FeatureOperation
	Fields    []FeatureField
}

type featureCommandState struct {
	spec                FeatureCommandSpec
	code                *authentication.OneTimeCode
	preAuthCookie       *authentication.BearerCredential
	sessionToken        *authentication.BearerCredential
	passwordHash        func() string
	passwordChange      func() (string, authentication.BearerCredential, authentication.ReauthenticationProof)
	passwordSignin      func() (primitive.Secret, authentication.BearerCredential)
	passwordSignup      func() (string, authentication.BearerCredential)
	passwordSignupInput func() (primitive.Secret, authentication.BearerCredential)
}

// NewFeatureCommand validates and freezes structural feature input, copying
// every field and binary value. It conveys no authentication, authorization,
// current state, freshness or execution readiness. The sole durable owner must
// match the exact registered descriptor and validate the full feature schema
// before computing its keyed fingerprint and admitting any phase. Current
// kernel coordinator execution/receipt paths do not accept this variant.
// Invalid input returns redacted InvalidInputError; zero is invalid. Pure,
// bounded construction performs no I/O/callbacks and starts no goroutines.
func NewFeatureCommand(spec FeatureCommandSpec) (Command, error) {
	if spec.Binding.ValidateFor(spec.Operation) != nil || !validFeatureFields(spec.Fields) {
		return Command{}, invalidFeatureCommand()
	}
	spec = cloneFeatureSpec(spec)
	slices.SortFunc(spec.Fields, func(a, b FeatureField) int { return strings.Compare(a.Name, b.Name) })
	return Command{feature: &featureCommandState{spec: spec}}, nil
}

func validFeatureFields(fields []FeatureField) bool {
	if len(fields) > 128 {
		return false
	}
	total := 0
	for i, field := range fields {
		if !validFeatureName(field.Name, '.') {
			return false
		}
		n, ok := featureValueSize(field.Value)
		if !ok || n+len(field.Name)+1 > (256<<10)-total {
			return false
		}
		total += n + len(field.Name) + 1
		for _, previous := range fields[:i] {
			if previous.Name == field.Name {
				return false
			}
		}
	}
	return true
}

// Feature returns an owned projection for trusted adapter schema mapping and
// false for zero, kernel, mixed or password-custody commands. Password owners
// must explicitly select their matching metadata/custody pair; older
// coordinators cannot silently omit verifier or submitted password material.
// Mutating returned fields or Bytes
// cannot change retained command intent. Copies of Command are immutable and
// safe for concurrent reads. The projection must never become a log, snapshot,
// public response or authentication decision. No callbacks or I/O run.
func (c Command) Feature() (FeatureCommandSpec, bool) {
	if !c.validFeatureVariant() || c.feature.passwordHash != nil || c.feature.passwordChange != nil || c.feature.passwordSignin != nil || c.feature.passwordSignup != nil || c.feature.passwordSignupInput != nil {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

func (c Command) validFeatureVariant() bool {
	return c.feature != nil && c.create == nil && c.update == nil && c.profile == nil && c.status == nil && c.unlink == nil && c.link == nil && c.identifier == nil && c.privacy == nil && !(c.feature.preAuthCookie != nil && c.feature.sessionToken != nil) && (c.feature.passwordSignupInput == nil || c.feature.code == nil && c.feature.preAuthCookie == nil && c.feature.sessionToken == nil && c.feature.passwordHash == nil && c.feature.passwordChange == nil && c.feature.passwordSignin == nil && c.feature.passwordSignup == nil)
}

func cloneFeatureSpec(s FeatureCommandSpec) FeatureCommandSpec {
	b := &s.Binding
	b.CommandID = CommandID(strings.Clone(string(b.CommandID)))
	b.TenantID = TenantID(strings.Clone(string(b.TenantID)))
	b.UserID = UserID(strings.Clone(string(b.UserID)))
	b.AnonymousFlowID = strings.Clone(b.AnonymousFlowID)
	b.ActorID = ActorID(strings.Clone(string(b.ActorID)))
	b.ActorKind = authorization.SubjectKind(strings.Clone(string(b.ActorKind)))
	b.OperationID, b.PolicyID, b.SchemaID = strings.Clone(b.OperationID), strings.Clone(b.PolicyID), strings.Clone(b.SchemaID)
	b.CorrelationID, b.RecordID = strings.Clone(b.CorrelationID), strings.Clone(b.RecordID)
	s.Operation.Owner = strings.Clone(s.Operation.Owner)
	s.Operation.OperationID = strings.Clone(s.Operation.OperationID)
	s.Operation.SchemaID = strings.Clone(s.Operation.SchemaID)
	s.Fields = slices.Clone(s.Fields)
	for i := range s.Fields {
		f := &s.Fields[i]
		f.Name, f.Value.Text = strings.Clone(f.Name), strings.Clone(f.Value.Text)
		f.Value.Bytes = slices.Clone(f.Value.Bytes)
		if f.Value.Kind == FeatureTime {
			f.Value.Time = f.Value.Time.UTC()
		}
	}
	return s
}

func featureValueSize(v FeatureValue) (int, bool) {
	size := 8
	switch v.Kind {
	case FeatureText:
		if len(v.Text) > 8192 || !utf8.ValidString(v.Text) {
			return 0, false
		}
		size, v.Text = len(v.Text), ""
	case FeatureBytes:
		if len(v.Bytes) > 8192 {
			return 0, false
		}
		size, v.Bytes = len(v.Bytes), nil
	case FeatureUint64:
		v.Uint64 = 0
	case FeatureInt64:
		v.Int64 = 0
	case FeatureBool:
		size, v.Bool = 1, false
	case FeatureTime:
		if v.Time.IsZero() || v.Time.UTC().Year() < 1 || v.Time.UTC().Year() > 9999 || v.Time.Nanosecond()%1000 != 0 {
			return 0, false
		}
		v.Time = time.Time{}
	default:
		return 0, false
	}
	return size, v.Text == "" && v.Bytes == nil && v.Uint64 == 0 && v.Int64 == 0 && !v.Bool && v.Time == (time.Time{})
}

func invalidFeatureCommand() error { return InvalidInputError{Field: "feature_command"} }
