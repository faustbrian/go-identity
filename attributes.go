package identity

import (
	"context"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
)

// AttributeKind is a closed lossless value kind. The empty kind is invalid.
type AttributeKind string

const (
	AttributeString AttributeKind = "string"
	AttributeBool   AttributeKind = "bool"
	AttributeInt64  AttributeKind = "int64"
	AttributeTime   AttributeKind = "time"
	// AttributeStringList is a list of at most 64 string scalars, not a scalar.
	AttributeStringList AttributeKind = "string-list"
)

// Cardinality distinguishes scalar presence from list presence. A nil list is
// absent; an allocated empty list is a valid explicit empty replacement.
type Cardinality string

const (
	CardinalityScalar Cardinality = "scalar"
	CardinalityList   Cardinality = "list"
)

// NormalizationPolicy names a versioned composition-owned normalization rule.
// Identity delegates these rules; it does not own another Unicode/phone engine.
type NormalizationPolicy string

const (
	NormalizeNone       NormalizationPolicy = "none"
	NormalizeUnicodeNFC NormalizationPolicy = "unicode-nfc"
	NormalizeCaseFold   NormalizationPolicy = "case-fold"
	NormalizeEmail      NormalizationPolicy = "email"
	NormalizePhone      NormalizationPolicy = "phone"
)

// FieldPermission is an explicit input or output permission, not authorization.
type FieldPermission string

const (
	FieldDenied    FieldPermission = "denied"
	FieldRead      FieldPermission = "read"
	FieldWrite     FieldPermission = "write"
	FieldReadWrite FieldPermission = "read-write"
)

// FieldAuthorization is a required write class passed to the upstream policy
// service. Administrator/system strings never grant a caller either role.
type FieldAuthorization string

const (
	FieldWriteSelf          FieldAuthorization = "self"
	FieldWriteAdministrator FieldAuthorization = "administrator"
	FieldWriteSystem        FieldAuthorization = "system"
)

// Sensitivity is the registered data classification. Secret fields cannot be
// indexed or made output-readable. These values must never hold credentials.
type Sensitivity string

const (
	SensitivityPublic    Sensitivity = "public"
	SensitivityPersonal  Sensitivity = "personal"
	SensitivitySensitive Sensitivity = "sensitive"
	SensitivitySecret    Sensitivity = "secret"
)

// AttributeScalar is a tagged scalar. Only its selected arm may be populated;
// false, integer zero and empty string are valid present values. Time must be
// nonzero; preparation returns UTC. Strings are valid UTF-8 and at most 4096
// bytes. There is deliberately no float conversion or arbitrary JSON payload.
type AttributeScalar struct {
	Kind   AttributeKind
	String string
	Bool   bool
	Int64  int64
	Time   time.Time
}

// AttributeValue is one scalar or a homogeneous bounded string list. An empty
// Kind is absent only for an entirely zero default; it is invalid in updates.
// Configure/submit values without concurrent mutation. Results own their lists.
type AttributeValue struct {
	Kind   AttributeKind
	Scalar AttributeScalar
	List   []AttributeScalar
}

// AttributeUpdate is one named whole-value replacement, not a patch language.
type AttributeUpdate struct {
	Name  string
	Value AttributeValue
}

// FieldPolicy defines one immutable additional field. Names use lower ASCII
// letters, digits and underscores, start with a letter and are 1..128 bytes.
// Core id/tenant_id/status/version names are reserved. Defaults must match kind
// and cardinality. Indexed=false is valid. MigrationVersion must equal the
// schema Version; incompatible versions require an explicit new schema.
type FieldPolicy struct {
	Name               string
	Kind               AttributeKind
	Cardinality        Cardinality
	Default            AttributeValue
	Normalization      NormalizationPolicy
	InputPermission    FieldPermission
	OutputPermission   FieldPermission
	WriteAuthorization FieldAuthorization
	Sensitivity        Sensitivity
	Indexed            bool
	MigrationVersion   uint32
}

// AttributeSchema declares 1..128 unique fields and positive migration version.
// NewAttributeProcessor snapshots it; later caller changes have no effect.
type AttributeSchema struct {
	ID      string
	Version uint32
	Fields  []FieldPolicy
}

// NormalizeAttributeFunc normalizes one admitted string scalar. The injected
// implementation must use stable versioned rules, preserve kind, honor context
// and be side-effect-free/concurrent-safe. Errors and panics are redacted.
type NormalizeAttributeFunc func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error)

// ValidateAttributeFunc applies the composition's versioned field constraints
// after normalization and intrinsic bounds. Inputs are private copies; mutation
// cannot change prepared values or retained defaults. Implementations must be
// side-effect-free, bounded, concurrent-safe and contain no stores/workflows.
type ValidateAttributeFunc func(context.Context, FieldPolicy, AttributeValue) error

// AttributeProcessorConfig binds trusted time, policy revision and canonical
// directory-ID validation. MaximumDuration is positive and at most one minute;
// no implicit defaults. The processor samples Clock once per preparation.
type AttributeProcessorConfig struct {
	Clock                   clock.Clock
	MaximumDuration         time.Duration
	PolicyVersion           uint64
	ValidateCanonicalUserID CanonicalUserIDValidator
	ValidateValue           ValidateAttributeFunc
}

// AttributePrepareRequest is trusted command composition, not a client-decoded
// authorization context. Supported actions are identity.user.create,
// identity.profile.update and identity.user.update-admin; only create fills
// absent defaults. SchemaVersion is exact, not a request to auto-migrate.
type AttributePrepareRequest struct {
	TenantID      TenantID
	UserID        UserID
	SchemaVersion uint32
	Updates       []AttributeUpdate
	Context       authorization.DecisionContext
}

// AttributeProcessor validates, normalizes and authorizes command values. It
// owns no stores, transactions, goroutines or locks and is concurrent-safe if
// its injected dependencies are. Prepared values are NOT a proof or a durable
// mutation: the command owner must bind/authorize/version-fence/persist them
// atomically. Output permissions still require projection/redaction at reads.
type AttributeProcessor struct {
	schema    AttributeSchema
	authorize authorization.Service
	normalize NormalizeAttributeFunc
	config    AttributeProcessorConfig
}

// NewAttributeProcessor validates and deep-copies composition without callbacks
// or I/O. A missing/typed-nil dependency, malformed schema or default is rejected.
func NewAttributeProcessor(schema AttributeSchema, authorize authorization.Service, normalize NormalizeAttributeFunc, config AttributeProcessorConfig) (*AttributeProcessor, error) {
	if nilDependency(authorize) || nilDependency(config.Clock) || normalize == nil || config.ValidateCanonicalUserID == nil || config.ValidateValue == nil || config.PolicyVersion == 0 || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute {
		return nil, InvalidInputError{Field: "attribute_configuration"}
	}
	if err := schema.Validate(); err != nil {
		return nil, err
	}
	schema.Fields = slices.Clone(schema.Fields)
	for i := range schema.Fields {
		schema.Fields[i].Default = cloneAttribute(schema.Fields[i].Default)
	}
	return &AttributeProcessor{schema: schema, authorize: authorize, normalize: normalize, config: config}, nil
}

// Validate checks a schema structurally without granting input, write or read
// authority. Scalar kinds require scalar cardinality; only StringList uses list
// cardinality. Normalization applies only to strings. Defaults across the
// schema and values across one command have a 256 KiB string payload budget.
func (s AttributeSchema) Validate() error {
	if !validDirectoryID(s.ID) || s.Version == 0 || len(s.Fields) == 0 || len(s.Fields) > 128 {
		return InvalidInputError{Field: "attribute_schema"}
	}
	total := 0
	for i, f := range s.Fields {
		if !validFieldName(f.Name) || reservedFieldName(f.Name) || f.MigrationVersion != s.Version || !validAttributeKind(f.Kind) || f.Cardinality != cardinalityFor(f.Kind) || !validNormalization(f.Normalization) || f.Normalization != NormalizeNone && f.Kind != AttributeString && f.Kind != AttributeStringList || !validPermission(f.InputPermission) || !validPermission(f.OutputPermission) || !validWriteClass(f.WriteAuthorization) || !validSensitivity(f.Sensitivity) || f.Sensitivity == SensitivitySecret && (f.Indexed || readable(f.OutputPermission)) {
			return InvalidInputError{Field: "field_policy"}
		}
		for _, previous := range s.Fields[:i] {
			if previous.Name == f.Name {
				return InvalidInputError{Field: "field_policy"}
			}
		}
		if f.Default.Kind == "" {
			if !zeroAttribute(f.Default) {
				return InvalidInputError{Field: "attribute_default"}
			}
		} else {
			n, ok := attributeSize(f.Default, f.Kind)
			if !ok || n > attributeBudget-total {
				return InvalidInputError{Field: "attribute_default"}
			}
			total += n
		}
	}
	return nil
}

const attributeBudget = 256 << 10

// Prepare returns ordered caller-owned values only if the whole request is
// valid and authorized at the configured revision. The operation and every
// field (including create defaults) require Allow. Self fields additionally
// require a user actor whose ID equals the target. Policy callbacks receive
// schema/field/class/sensitivity metadata, never attribute contents. Reserved
// metadata is replaced, not accepted from callers. No partial output survives
// a deny, cancellation, malformed callback output, dependency error or panic.
func (p *AttributeProcessor) Prepare(ctx context.Context, req AttributePrepareRequest) (result []AttributeUpdate, err error) {
	return p.prepare(ctx, req, time.Time{})
}

// Creation shares its single trusted sample with the same field implementation.
// No public caller can override the field processor's decision time.
func (p *AttributeProcessor) prepare(ctx context.Context, req AttributePrepareRequest, decisionTime time.Time) (result []AttributeUpdate, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = UnavailableError{}
		}
	}()
	if p == nil || ctx == nil {
		return nil, InvalidInputError{Field: "attribute_context"}
	}
	action := string(req.Context.Request.Action)
	if action != "identity.user.create" && action != "identity.profile.update" && action != "identity.user.update-admin" {
		return nil, InvalidInputError{Field: "attribute_operation"}
	}
	if err := validateQueryContext(req.Context, req.TenantID, string(req.UserID), action, "identity.user", p.config.PolicyVersion); err != nil {
		return nil, err
	}
	if req.SchemaVersion != p.schema.Version || len(req.Updates) > 128 {
		return nil, InvalidInputError{Field: "attribute_updates"}
	}
	// Validate all supplied values and the combined default payload before copies,
	// callbacks or authorization work. This also prevents hidden partial writes.
	prepared := make([]AttributeUpdate, 0, len(p.schema.Fields))
	total := 0
	for i, update := range req.Updates {
		field, ok := p.field(update.Name)
		if !ok {
			return nil, InvalidInputError{Field: "attribute_updates"}
		}
		for _, previous := range req.Updates[:i] {
			if previous.Name == update.Name {
				return nil, InvalidInputError{Field: "attribute_updates"}
			}
		}
		if !writable(field.InputPermission) {
			return nil, ForbiddenError{}
		}
		n, ok := attributeSize(update.Value, field.Kind)
		if !ok || n > attributeBudget-total {
			return nil, InvalidInputError{Field: "attribute_value"}
		}
		total += n
	}
	for _, field := range p.schema.Fields {
		value := field.Default
		present := action == "identity.user.create" && value.Kind != ""
		for _, update := range req.Updates {
			if update.Name == field.Name {
				value, present = update.Value, true
				break
			}
		}
		if !present {
			continue
		}
		if field.WriteAuthorization == FieldWriteSelf && (req.Context.Request.Subject.Kind != authorization.SubjectUser || string(req.Context.Request.Subject.ID) != string(req.UserID)) {
			return nil, ForbiddenError{}
		}
		prepared = append(prepared, AttributeUpdate{Name: field.Name, Value: value})
	}
	total = 0
	for _, update := range prepared {
		n, _ := attributeSize(update.Value, update.Value.Kind)
		if n > attributeBudget-total {
			return nil, InvalidInputError{Field: "attribute_value"}
		}
		total += n
	}
	for i := range prepared {
		prepared[i].Value = cloneAttribute(prepared[i].Value)
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.MaximumDuration)
	defer cancel()
	if err := readContextError(ctx); err != nil {
		return nil, err
	}
	if err := p.config.ValidateCanonicalUserID(ctx, req.UserID); err != nil {
		if e := readContextError(ctx); e != nil {
			return nil, e
		}
		return nil, InvalidInputError{Field: "user_id"}
	}
	if err := readContextError(ctx); err != nil {
		return nil, err
	}
	now := decisionTime
	if now.IsZero() {
		now = p.config.Clock.Now()
	}
	if now.IsZero() {
		return nil, UnavailableError{}
	}
	dc := req.Context.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for _, key := range []authorization.AttributeName{"identity.field", "identity.field.write_class", "identity.field.sensitivity"} {
		delete(dc.Request.Resource.Attributes, key)
	}
	dc.Request.Resource.Attributes["identity.schema.id"] = authorization.StringValue(p.schema.ID)
	dc.Request.Resource.Attributes["identity.schema.version"] = authorization.IntValue(int64(p.schema.Version))
	names := make([]string, len(prepared))
	for i := range prepared {
		names[i] = prepared[i].Name
	}
	// Authorization string sets are bounded at 64 entries; two fixed partitions
	// retain the complete admitted 128-field operation without unbounded values.
	split := min(len(names), 64)
	dc.Request.Resource.Attributes["identity.fields.first"] = authorization.StringSetValue(names[:split])
	dc.Request.Resource.Attributes["identity.fields.second"] = authorization.StringSetValue(names[split:])
	if err := p.allow(ctx, dc); err != nil {
		return nil, err
	}
	total = 0
	for i := range prepared {
		field, _ := p.field(prepared[i].Name)
		value := prepared[i].Value
		if field.Normalization != NormalizeNone {
			if value.Kind == AttributeStringList {
				for j := range value.List {
					normalized, e := p.normalize(ctx, field.Normalization, value.List[j])
					if e != nil {
						if e := readContextError(ctx); e != nil {
							return nil, e
						}
						return nil, UnavailableError{}
					}
					value.List[j] = normalized
					if e := readContextError(ctx); e != nil {
						return nil, e
					}
				}
			} else {
				normalized, e := p.normalize(ctx, field.Normalization, value.Scalar)
				if e != nil {
					if e := readContextError(ctx); e != nil {
						return nil, e
					}
					return nil, UnavailableError{}
				}
				value.Scalar = normalized
			}
		}
		if e := readContextError(ctx); e != nil {
			return nil, e
		}
		n, ok := attributeSize(value, field.Kind)
		if !ok || n > attributeBudget-total {
			return nil, UnavailableError{}
		}
		total += n
		if value.Kind == AttributeTime {
			value.Scalar.Time = value.Scalar.Time.UTC()
		}
		prepared[i].Value = value
		field.Default = cloneAttribute(field.Default)
		validationErr := p.config.ValidateValue(ctx, field, cloneAttribute(value))
		if e := readContextError(ctx); e != nil {
			return nil, e
		}
		if validationErr != nil {
			return nil, InvalidInputError{Field: "attribute_value"}
		}
		fdc := dc.Clone()
		fdc.Request.Resource.Attributes["identity.field"] = authorization.StringValue(field.Name)
		fdc.Request.Resource.Attributes["identity.field.write_class"] = authorization.StringValue(string(field.WriteAuthorization))
		fdc.Request.Resource.Attributes["identity.field.sensitivity"] = authorization.StringValue(string(field.Sensitivity))
		if err := p.allow(ctx, fdc); err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

func (p *AttributeProcessor) allow(ctx context.Context, dc authorization.DecisionContext) error {
	if len(dc.Request.Resource.Attributes) > 128 {
		return InvalidInputError{Field: "authorization_attributes"}
	}
	d, err := p.authorize.Decide(ctx, dc)
	if e := readContextError(ctx); e != nil {
		return e
	}
	if err != nil {
		return UnavailableError{}
	}
	if d.Outcome != authorization.Allow || d.Revision != authorization.Revision(p.config.PolicyVersion) {
		return ForbiddenError{}
	}
	return nil
}

func (p *AttributeProcessor) field(name string) (FieldPolicy, bool) {
	for _, f := range p.schema.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return FieldPolicy{}, false
}

func cloneAttribute(v AttributeValue) AttributeValue { v.List = slices.Clone(v.List); return v }
func zeroAttribute(v AttributeValue) bool {
	return v.Kind == "" && v.Scalar == (AttributeScalar{}) && v.List == nil
}
func cardinalityFor(k AttributeKind) Cardinality {
	if k == AttributeStringList {
		return CardinalityList
	}
	return CardinalityScalar
}
func validAttributeKind(k AttributeKind) bool {
	return k == AttributeString || k == AttributeBool || k == AttributeInt64 || k == AttributeTime || k == AttributeStringList
}
func validNormalization(n NormalizationPolicy) bool {
	return n == NormalizeNone || n == NormalizeUnicodeNFC || n == NormalizeCaseFold || n == NormalizeEmail || n == NormalizePhone
}
func validPermission(p FieldPermission) bool {
	return p == FieldDenied || p == FieldRead || p == FieldWrite || p == FieldReadWrite
}
func writable(p FieldPermission) bool { return p == FieldWrite || p == FieldReadWrite }
func readable(p FieldPermission) bool { return p == FieldRead || p == FieldReadWrite }
func validWriteClass(a FieldAuthorization) bool {
	return a == FieldWriteSelf || a == FieldWriteAdministrator || a == FieldWriteSystem
}
func validSensitivity(s Sensitivity) bool {
	return s == SensitivityPublic || s == SensitivityPersonal || s == SensitivitySensitive || s == SensitivitySecret
}
func validFieldName(name string) bool {
	if len(name) == 0 || len(name) > 128 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				if c != '_' {
					return false
				}
			}
		}
	}
	return true
}

func reservedFieldName(name string) bool {
	return name == "id" || name == "tenant_id" || name == "status" || name == "version"
}

func attributeSize(v AttributeValue, kind AttributeKind) (int, bool) {
	if v.Kind != kind || !validAttributeKind(kind) {
		return 0, false
	}
	if kind != AttributeStringList {
		if v.List != nil || v.Scalar.Kind != kind {
			return 0, false
		}
		return scalarSize(v.Scalar)
	}
	if v.Scalar != (AttributeScalar{}) || v.List == nil || len(v.List) > 64 {
		return 0, false
	}
	total := 0
	for _, s := range v.List {
		if s.Kind != AttributeString {
			return 0, false
		}
		n, ok := scalarSize(s)
		if !ok {
			return 0, false
		}
		total += n
	}
	return total, true
}

func scalarSize(s AttributeScalar) (int, bool) {
	switch s.Kind {
	case AttributeString:
		return len(s.String), len(s.String) <= 4096 && utf8.ValidString(s.String) && !s.Bool && s.Int64 == 0 && s.Time == (time.Time{})
	case AttributeBool:
		return 0, s.String == "" && s.Int64 == 0 && s.Time == (time.Time{})
	case AttributeInt64:
		return 0, s.String == "" && !s.Bool && s.Time == (time.Time{})
	case AttributeTime:
		return 0, s.String == "" && !s.Bool && s.Int64 == 0 && !s.Time.IsZero()
	default:
		return 0, false
	}
}
