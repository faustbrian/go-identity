package identityhttp

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

// ModuleID is an explicit case-sensitive feature or accountable module ID.
// IDs contain 1..128 lowercase ASCII letters, digits, dots, dashes and slashes;
// separators cannot be leading, trailing or adjacent. IDs confer no authority.
type ModuleID string

// Exposure identifies canonical transport disposition. Zero is invalid.
// Routed descriptors accept only Both and Protocol. Direct/middleware coverage
// belongs to the complete acceptance catalog, not fabricated HTTP handlers.
type Exposure uint8

const (
	ExposureBoth Exposure = iota + 1
	ExposureDirect
	ExposureProtocol
	ExposureMiddleware
)

// CSRFMode identifies the required protection, not proof it has been enforced.
type CSRFMode uint8

const (
	CSRFNone CSRFMode = iota + 1
	CSRFExactOrigin
	CSRFSessionOriginAndToken
	CSRFConditionalPreAuthSession
	CSRFBoundOrigin
	// CSRFSessionState requires exact origin for cookie-mode requests and the
	// current session-bound synchronizer token for active sessions. Absent or
	// inactive self-signout needs origin only. Token lifetime follows active
	// session state; no independent token-age bound is claimed.
	CSRFSessionState
	// CSRFVariantOriginSessionState requires exact Origin for the explicitly
	// selected login variant and original stored-session synchronizer plus Origin
	// for enrollment confirmation. No independent token age is minted.
	CSRFVariantOriginSessionState
)

// RefererFallbackPolicy is explicit when a CSRF variant uses origin protection.
type RefererFallbackPolicy uint8

const (
	RefererFallbackDeny RefererFallbackPolicy = iota + 1
	RefererFallbackSameOriginHTTPS
)

// CSRFPolicy is a closed discriminated policy. SessionOriginAndToken and
// ConditionalPreAuthSession require TokenHeader (1..128 HTTP-token bytes) and
// TokenMaximumAge (positive, at most 24h). SessionState requires TokenHeader but
// zero TokenMaximumAge, binding lifetime to active session state instead.
// VariantOriginSessionState applies that stored-token lifetime only to the
// explicit enrollment branch; login requires exact Origin.
// RefererFallback is required except for None, where it must be zero.
type CSRFPolicy struct {
	Mode            CSRFMode
	TokenHeader     string
	TokenMaximumAge time.Duration
	RefererFallback RefererFallbackPolicy
}

// RatePolicyID names one complete canonical multi-bucket rate policy. A named
// binding does not prove admission, counter atomicity or outage handling. The
// later transport limiter must expand this ID through its owned rate catalog;
// it must not approximate multiple buckets with one window/burst override.
type RatePolicyID string

// RouteAuthorization records explicit access and authorization policy text,
// respectively 1..256 and 1..512 printable ASCII bytes. It is not an authorizer.
type RouteAuthorization struct{ Access, Policy string }

// TypedSchema identifies a public contract, nonzero content digest and depth
// bound (1..128). IDs are 1..256 printable non-space ASCII bytes. This summary
// is not a rendered or validated JSON Schema or OpenAPI document.
type TypedSchema struct {
	ID           string
	Digest       [32]byte
	MaximumDepth uint32
}

// OpenAPISchema declares one globally unique component name (1..128 ASCII
// identifier bytes), its typed identity, and positive serialized limit <=16MiB.
// Schema material/rendering remains owned by the later OpenAPI builder.
type OpenAPISchema struct {
	Name                   string
	Schema                 TypedSchema
	MaximumSerializedBytes uint64
}

// Route records an exact method/path and the same policy as its operation.
// Supported methods are GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS. Paths
// contain 1..2048 ASCII bytes, start with / and cannot contain escapes, query,
// fragments, repeated separators or dot segments. No path normalization occurs.
type Route struct {
	Method, Path  string
	Authorization RouteAuthorization
	CSRF          CSRFPolicy
	RatePolicy    RatePolicyID
}

// OperationRecord is selected operation metadata. Owners contains 1..16 unique
// module IDs with the accountable owner first. Admission limits are 128 bytes
// for operation identifiers, 32 for risk/idempotency and 4096 for event semantics.
// Canonical records must match the pinned catalog; extension IDs are namespaced.
// This is neither full canonical coverage nor evidence of security enforcement.
type OperationRecord struct {
	OperationID                              string
	Exposure                                 Exposure
	Owners                                   []ModuleID
	Access                                   string
	Authorization                            RouteAuthorization
	CSRFOrigin                               CSRFPolicy
	RiskClass                                string
	RatePolicy                               RatePolicyID
	Idempotency, EventSemantics              string
	RequestSchema, ResultSchema, ErrorSchema TypedSchema
	HandlerOwner                             ModuleID
	Method, Path, OpenAPIOperationID         string
}

// OperationDescriptor pairs metadata with a real feature-owned handler and
// 3..64 component declarations including its request/result/error summaries.
// Handlers must be usable concurrent-safe values; typed-nil HandlerFunc is
// rejected, other implementation validity is the feature owner's contract.
// Do not serve a descriptor directly as an identity endpoint: it is input to the
// future security router, not a replacement for authentication/rate/CSRF work.
type OperationDescriptor struct {
	Record  OperationRecord
	Route   Route
	Handler http.Handler
	Schemas []OpenAPISchema
	// Wire is separate from canonical direct-contract summaries. Nil retains
	// compatibility for undisclosed routes but cannot enter documented composition.
	Wire *WireOperation
}

// FeatureConfig supplies one feature-owned integration's actual handlers.
// ID owns its canonical operations or the extension.<ID with slashes replaced
// by dots> namespace. Requires contains at most 64 distinct other selected IDs.
// Operations contains 1..1024 routed contributions. Feature factories must
// validate their actual typed service dependencies before calling NewFeature;
// dependency IDs alone cannot certify a usable domain service.
type FeatureConfig struct {
	ID         ModuleID
	Requires   []ModuleID
	Operations []OperationDescriptor
}

// Feature is a validated immutable contribution, not a service locator. Its zero
// value is invalid. Inputs/getters are deeply copied except borrowed handlers,
// whose concurrent execution/resources remain their feature owner's contract.
// It can be shared across independently constructed selections without locks.
type Feature struct {
	id         ModuleID
	requires   []ModuleID
	operations []OperationDescriptor
}

// ID returns the contribution identity; a zero feature returns empty.
func (f Feature) ID() ModuleID { return f.id }

// Operations returns detached descriptor metadata. Handler values are borrowed,
// not cloned or closed; mutating a handler's internals is not snapshot mutation.
func (f Feature) Operations() []OperationDescriptor { return cloneOperations(f.operations) }

// FeatureServices selects only the supplied validated contributions. Empty is a
// valid selection with no routes, probes, schemas or advertised capabilities.
// No global registry, optional feature imports or implicit default feature exist.
type FeatureServices struct{ Features []Feature }

// NewFeature validates then copies a single contribution without IO or handler
// invocation. It rejects malformed metadata, missing handlers, local collisions,
// wrong canonical policies/ownership and non-routed catalog rows. Missing selected
// dependencies and cross-feature collisions are rejected by selection. Callers
// must not mutate input slices concurrently with construction.
func NewFeature(config FeatureConfig) (Feature, error) {
	if !moduleID(config.ID) || len(config.Requires) > 64 || len(config.Operations) == 0 || len(config.Operations) > 1024 {
		return Feature{}, ErrInvalidInput
	}
	deps := make(map[ModuleID]bool, len(config.Requires))
	for _, id := range config.Requires {
		if !moduleID(id) || id == config.ID || deps[id] {
			return Feature{}, ErrInvalidInput
		}
		deps[id] = true
	}
	catalog := readCatalog()
	wireBytes := 0
	for _, op := range config.Operations {
		if !validWireBounds(op.Wire) {
			return Feature{}, ErrInvalidInput
		}
		wireBytes += wireSize(op.Wire)
		if !validOperation(config.ID, op, catalog) || wireBytes > 4<<20 {
			return Feature{}, ErrInvalidInput
		}
	}
	if !uniqueOperations(config.Operations) {
		return Feature{}, ErrInvalidInput
	}
	f := Feature{id: config.ID, requires: slices.Clone(config.Requires), operations: cloneOperations(config.Operations)}
	slices.Sort(f.requires)
	slices.SortFunc(f.operations, func(a, b OperationDescriptor) int { return strings.Compare(a.Record.OperationID, b.Record.OperationID) })
	return f, nil
}

// NewOperationDescriptors validates a complete selected dependency graph, then
// returns detached canonical-ID-sorted descriptors. Limits are 64 features,
// 1024 aggregate operations and 4096 aggregate components. Identical as well as
// conflicting duplicate IDs/routes/components reject atomically. Cycles/missing
// dependencies reject independently of input order; zero Feature values reject.
// An empty feature list is valid and selects nothing. It
// performs no IO/callbacks and returns no partial result on error.
//
// Device-token is a token-endpoint request variant, not a standalone descriptor;
// it is rejected here until the owned token dispatcher/variant composition is
// implemented. Full direct/middleware coverage and security/OpenAPI composition
// remain distinct required work, not inferred from this selected routed list.
func NewOperationDescriptors(services FeatureServices) ([]OperationDescriptor, error) {
	if len(services.Features) > 64 {
		return nil, ErrInvalidInput
	}
	features := make(map[ModuleID]Feature, len(services.Features))
	count, schemas, wireBytes := 0, 0, 0
	for _, f := range services.Features {
		if f.id == "" {
			return nil, ErrInvalidInput
		}
		if _, ok := features[f.id]; ok {
			return nil, ErrInvalidInput
		}
		features[f.id] = f
		count += len(f.operations)
		for _, op := range f.operations {
			schemas += len(op.Schemas)
			wireBytes += wireSize(op.Wire)
		}
		if count > 1024 || schemas > 4096 || wireBytes > 16<<20 {
			return nil, ErrInvalidInput
		}
	}
	marks := make(map[ModuleID]uint8, len(features))
	var visit func(ModuleID) bool
	visit = func(id ModuleID) bool {
		if marks[id] == 1 {
			return false
		}
		if marks[id] == 2 {
			return true
		}
		f, ok := features[id]
		if !ok {
			return false
		}
		marks[id] = 1
		for _, required := range f.requires {
			if !visit(required) {
				return false
			}
		}
		marks[id] = 2
		return true
	}
	for id := range features {
		if !visit(id) {
			return nil, ErrInvalidInput
		}
	}
	result := make([]OperationDescriptor, 0, count)
	for _, f := range services.Features {
		result = append(result, f.operations...)
	}
	if !uniqueOperations(result) {
		return nil, ErrInvalidInput
	}
	result = cloneOperations(result)
	slices.SortFunc(result, func(a, b OperationDescriptor) int { return strings.Compare(a.Record.OperationID, b.Record.OperationID) })
	return result, nil
}

// NewProbeFeature is the owned opt-in probe contribution. It invokes no checks,
// selects no domain features and retains reference's accountable readiness
// ownership. Canonical schema summaries describe direct public contracts; the
// separate Wire contribution describes the fixed safe handler projection for
// NewDocumentedHandler. Direct summaries never become response schemas.
func NewProbeFeature(config ProbeConfig) (Feature, error) {
	live, ready, err := NewProbeHandlers(config)
	if err != nil {
		return Feature{}, err
	}
	catalog := readCatalog()
	ops := make([]OperationDescriptor, 0, 2)
	for i, id := range []string{"identity.health", "identity.readiness"} {
		row := catalog[id]
		r := row.record()
		r.RequestSchema = schemaSummary(row.RequestSchema, row.RequestDigest)
		r.ResultSchema = schemaSummary(row.ResultSchema, row.ResultDigest)
		r.ErrorSchema = schemaSummary(row.ErrorSchema, row.ErrorDigest)
		handler := live
		if i == 1 {
			handler = ready
		}
		components := make([]OpenAPISchema, 0, 3)
		for j, schema := range []TypedSchema{r.RequestSchema, r.ResultSchema, r.ErrorSchema} {
			components = append(components, OpenAPISchema{Name: strings.ReplaceAll(id, ".", "_") + []string{"_request", "_result", "_error"}[j], Schema: schema, MaximumSerializedBytes: 16384})
		}
		ops = append(ops, OperationDescriptor{Record: r, Route: Route{Method: r.Method, Path: r.Path, Authorization: r.Authorization, CSRF: r.CSRFOrigin, RatePolicy: r.RatePolicy}, Handler: handler, Schemas: components, Wire: probeWire(id)})
	}
	return NewFeature(FeatureConfig{ID: "identity/http.probes", Operations: ops})
}

func schemaSummary(id, digest string) TypedSchema {
	// Bind the actual canonical public-contract definition, not an invented
	// schema or a digest of its ID. This is still not a rendered JSON Schema.
	bytes, err := hex.DecodeString(digest)
	if err != nil || len(bytes) != 32 {
		panic("identityhttp: invalid owned schema digest")
	}
	return TypedSchema{ID: id, Digest: [32]byte(bytes), MaximumDepth: 128}
}

func cloneOperations(input []OperationDescriptor) []OperationDescriptor {
	result := make([]OperationDescriptor, len(input))
	for i, op := range input {
		op.Record.Owners = slices.Clone(op.Record.Owners)
		op.Schemas = slices.Clone(op.Schemas)
		op.Wire = cloneWire(op.Wire)
		result[i] = op
	}
	return result
}

func uniqueOperations(ops []OperationDescriptor) bool {
	ids, routes, names, schemas := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, op := range ops {
		key := op.Route.Method + " " + op.Route.Path
		if ids[op.Record.OperationID] || routes[key] {
			return false
		}
		ids[op.Record.OperationID], routes[key] = true, true
		for _, s := range op.Schemas {
			if names[s.Name] || schemas[s.Schema.ID] {
				return false
			}
			names[s.Name], schemas[s.Schema.ID] = true, true
		}
	}
	return true
}

func validOperation(owner ModuleID, op OperationDescriptor, catalog map[string]catalogOperation) bool {
	r := op.Record
	if !identifier(r.OperationID, 128) || !identifier(r.OpenAPIOperationID, 128) || (r.Exposure != ExposureBoth && r.Exposure != ExposureProtocol) || len(r.Owners) == 0 || len(r.Owners) > 16 || !moduleID(r.HandlerOwner) || !text(r.Access, 256) || !text(r.Authorization.Access, 256) || !text(r.Authorization.Policy, 512) || r.Access != r.Authorization.Access || !text(r.EventSemantics, 4096) || !validCSRF(r.CSRFOrigin) || !rateID(r.RatePolicy) {
		return false
	}
	owners := map[ModuleID]bool{}
	for _, id := range r.Owners {
		if !moduleID(id) || owners[id] {
			return false
		}
		owners[id] = true
	}
	if !slices.Contains([]string{"safe", "auth", "secret", "admin", "provider", "protocol"}, r.RiskClass) || !slices.Contains([]string{"read", "repeat", "keyed", "once", "rotate", "protocol-poll", "protocol-command", "none"}, r.Idempotency) {
		return false
	}
	if !validPath(r.Path) || !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}, r.Method) || op.Route != (Route{Method: r.Method, Path: r.Path, Authorization: r.Authorization, CSRF: r.CSRFOrigin, RatePolicy: r.RatePolicy}) || op.Handler == nil {
		return false
	}
	if f, ok := op.Handler.(http.HandlerFunc); ok && f == nil {
		return false
	}
	if len(op.Schemas) < 3 || len(op.Schemas) > 64 {
		return false
	}
	declared := make(map[string]TypedSchema, len(op.Schemas))
	for _, s := range op.Schemas {
		if !identifier(s.Name, 128) || !validSchema(s.Schema) || s.MaximumSerializedBytes == 0 || s.MaximumSerializedBytes > 16<<20 {
			return false
		}
		declared[s.Schema.ID] = s.Schema
	}
	for _, s := range []TypedSchema{r.RequestSchema, r.ResultSchema, r.ErrorSchema} {
		if !validSchema(s) || declared[s.ID] != s {
			return false
		}
	}
	if r.RequestSchema.ID == r.ResultSchema.ID || r.RequestSchema.ID == r.ErrorSchema.ID || r.ResultSchema.ID == r.ErrorSchema.ID {
		return false
	}
	if row, ok := catalog[r.OperationID]; ok {
		if row.OpenAPIID != row.ID {
			return false
		} // shared token route is not another handler
		want := row.record()
		// Canonical IDs bind content as well as names. Matching a caller's
		// component declarations alone would permit replacing the owned contract.
		if r.RequestSchema.Digest != schemaSummary(row.RequestSchema, row.RequestDigest).Digest || r.ResultSchema.Digest != schemaSummary(row.ResultSchema, row.ResultDigest).Digest || r.ErrorSchema.Digest != schemaSummary(row.ErrorSchema, row.ErrorDigest).Digest {
			return false
		}
		csrfMatches := r.CSRFOrigin.Mode == want.CSRFOrigin.Mode
		// A selected pre-auth-only integration may narrow the canonical union.
		// It must reject authenticated-session/MFA variants rather than treating
		// their ambient credentials as pre-auth authority. Never downgrade a
		// session-only row, or claim a token header the handler does not consume.
		if want.CSRFOrigin.Mode == CSRFConditionalPreAuthSession && r.CSRFOrigin.Mode == CSRFExactOrigin && r.CSRFOrigin.RefererFallback == RefererFallbackDeny {
			csrfMatches = true
		}
		// These owned operations select explicit bearer or stored-synchronizer
		// cookie profiles. Password change still requires an active session;
		// only self-signout admits absent/inactive origin-only success. Neither
		// stored-token profile claims an independent token-age bound.
		if (r.OperationID == "identity.session.signout" || r.OperationID == "identity.password.change") && (r.CSRFOrigin.Mode == CSRFNone || r.CSRFOrigin.Mode == CSRFSessionState) {
			csrfMatches = true
		}
		// Verification selects either strict bearer custody or the stored-session
		// synchronizer protected by its native transaction owner. Selection grants
		// no authority and does not issue or age an independent CSRF token.
		if r.OperationID == "identity.password.verify" && (r.CSRFOrigin.Mode == CSRFNone || (r.CSRFOrigin.Mode == CSRFSessionState && r.CSRFOrigin.RefererFallback == RefererFallbackDeny)) {
			csrfMatches = true
		}
		// Native cookie-only MFA enrollment authenticates the synchronizer
		// against original session state under mutation fences. It never issues
		// a separately aged CSRF token or admits an origin-only/bearer fallback.
		if (r.OperationID == "identity.mfa.enable" || r.OperationID == "identity.mfa.totp-uri" || r.OperationID == "identity.mfa.recovery-regenerate" || r.OperationID == "identity.mfa.factor-update" || r.OperationID == "identity.mfa.disable") && r.CSRFOrigin.Mode == CSRFSessionState && r.CSRFOrigin.TokenHeader == "X-CSRF-Token" && r.CSRFOrigin.RefererFallback == RefererFallbackDeny {
			csrfMatches = true
		}
		// Selected email requests authenticate the original stored synchronizer
		// in their native transaction. This is stricter than the public send
		// origin minimum, not an independently aged token or a bearer fallback.
		if (r.OperationID == "identity.email.verification-send" || r.OperationID == "identity.email.change-request" || r.OperationID == "identity.email.address-remove") && r.CSRFOrigin.Mode == CSRFSessionState && r.CSRFOrigin.TokenHeader == "X-CSRF-Token" && r.CSRFOrigin.RefererFallback == RefererFallbackDeny {
			csrfMatches = true
		}
		if r.OperationID == "identity.mfa.totp-verify" && (r.CSRFOrigin.Mode == CSRFSessionState || r.CSRFOrigin.Mode == CSRFVariantOriginSessionState) && r.CSRFOrigin.TokenHeader == "X-CSRF-Token" && r.CSRFOrigin.RefererFallback == RefererFallbackDeny {
			csrfMatches = true
		}
		if r.Exposure != want.Exposure || !slices.Equal(r.Owners, want.Owners) || r.Access != want.Access || r.Authorization != want.Authorization || !csrfMatches || r.RiskClass != want.RiskClass || r.RatePolicy != want.RatePolicy || r.Idempotency != want.Idempotency || r.EventSemantics != want.EventSemantics || r.HandlerOwner != want.HandlerOwner || r.Method != want.Method || r.Path != want.Path || r.OpenAPIOperationID != want.OpenAPIOperationID || r.RequestSchema.ID != row.RequestSchema || r.ResultSchema.ID != row.ResultSchema || r.ErrorSchema.ID != row.ErrorSchema {
			return false
		}
		return owner == r.Owners[0] || (owner == "identity/http.probes" && (r.OperationID == "identity.health" || r.OperationID == "identity.readiness"))
	}
	prefix := "extension." + strings.ReplaceAll(string(owner), "/", ".") + "."
	return strings.HasPrefix(r.OperationID, prefix) && len(r.OperationID) > len(prefix) && r.OpenAPIOperationID == r.OperationID && r.Owners[0] == owner && r.HandlerOwner == owner
}

func validSchema(s TypedSchema) bool {
	return ascii(s.ID, 256, false) && s.Digest != [32]byte{} && s.MaximumDepth >= 1 && s.MaximumDepth <= 128
}
func text(s string, max int) bool { return ascii(s, max, true) }
func ascii(s string, max int, space bool) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	minimum := byte(33)
	if space {
		minimum = 32
	}
	for i := range s {
		if s[i] < minimum || s[i] > 126 {
			return false
		}
	}
	return true
}
func identifier(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := range s {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func moduleID(id ModuleID) bool {
	s := string(id)
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	previous := true
	for i := range s {
		c := s[i]
		separator := c == '/' || c == '.' || c == '-'
		if separator && previous {
			return false
		}
		if !separator && !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
		previous = separator
	}
	return !previous
}
func validPath(p string) bool {
	return ascii(p, 2048, false) && p[0] == '/' && !strings.ContainsAny(p, "%?#\\") && !strings.Contains(p, "//") && !strings.Contains(p+"/", "/./") && !strings.Contains(p+"/", "/../")
}
func validCSRF(p CSRFPolicy) bool {
	if p.Mode < CSRFNone || p.Mode > CSRFVariantOriginSessionState {
		return false
	}
	if p.Mode == CSRFNone {
		return p.TokenHeader == "" && p.TokenMaximumAge == 0 && p.RefererFallback == 0
	}
	if p.RefererFallback != RefererFallbackDeny && p.RefererFallback != RefererFallbackSameOriginHTTPS {
		return false
	}
	if p.Mode != CSRFSessionOriginAndToken && p.Mode != CSRFConditionalPreAuthSession && p.Mode != CSRFSessionState && p.Mode != CSRFVariantOriginSessionState {
		return p.TokenHeader == "" && p.TokenMaximumAge == 0
	}
	stored := p.Mode == CSRFSessionState || p.Mode == CSRFVariantOriginSessionState
	if len(p.TokenHeader) == 0 || len(p.TokenHeader) > 128 || p.TokenMaximumAge > 24*time.Hour || (stored && p.TokenMaximumAge != 0) || (!stored && p.TokenMaximumAge <= 0) {
		return false
	}
	for i := range p.TokenHeader {
		c := p.TokenHeader[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
func rateID(id RatePolicyID) bool {
	return slices.Contains([]RatePolicyID{"rate.safe", "rate.auth", "rate.secret", "rate.admin", "rate.provider", "rate.protocol", "rate.signup", "rate.signin", "rate.delivery", "rate.verify", "rate.provider-callback", "rate.oauth-token", "rate.device-poll"}, id)
}

// operationCatalog is generated immutable build input, never a runtime registry.
//
//go:embed catalog.json
var operationCatalog string

type catalogOperation struct {
	ID            string       `json:"id"`
	Owners        []ModuleID   `json:"owners"`
	Exposure      string       `json:"exposure"`
	Access        string       `json:"access"`
	Authorization string       `json:"authorization"`
	CSRF          string       `json:"csrf_origin"`
	Risk          string       `json:"risk_class"`
	Rate          RatePolicyID `json:"rate_policy"`
	Idempotency   string       `json:"idempotency"`
	Events        string       `json:"event_semantics"`
	Method        string       `json:"http_method"`
	Path          string       `json:"http_path"`
	OpenAPIID     string       `json:"openapi_operation_id"`
	RequestSchema string       `json:"request_schema"`
	ResultSchema  string       `json:"result_schema"`
	ErrorSchema   string       `json:"error_schema"`
	RequestDigest string       `json:"request_digest"`
	ResultDigest  string       `json:"result_digest"`
	ErrorDigest   string       `json:"error_digest"`
}

func readCatalog() map[string]catalogOperation {
	var data struct {
		Operations []catalogOperation `json:"operations"`
	}
	// Corrupt owned build input is a programming defect, not caller data. The
	// generator and package tests validate this exact input before release.
	if err := json.Unmarshal([]byte(operationCatalog), &data); err != nil {
		panic("identityhttp: invalid owned catalog")
	}
	result := make(map[string]catalogOperation, len(data.Operations))
	for _, op := range data.Operations {
		result[op.ID] = op
	}
	return result
}

func (row catalogOperation) record() OperationRecord {
	exposure := ExposureBoth
	if row.Exposure == "protocol" {
		exposure = ExposureProtocol
	}
	if row.Exposure == "direct" {
		exposure = ExposureDirect
	}
	if row.Exposure == "middleware" {
		exposure = ExposureMiddleware
	}
	mode := map[string]CSRFMode{"none": CSRFNone, "origin": CSRFExactOrigin, "CSRF": CSRFSessionOriginAndToken, "origin or CSRF": CSRFConditionalPreAuthSession, "CSRF or origin": CSRFConditionalPreAuthSession, "exact bound origin": CSRFBoundOrigin}[row.CSRF]
	return OperationRecord{OperationID: row.ID, Exposure: exposure, Owners: slices.Clone(row.Owners), Access: row.Access, Authorization: RouteAuthorization{Access: row.Access, Policy: row.Authorization}, CSRFOrigin: CSRFPolicy{Mode: mode}, RiskClass: row.Risk, RatePolicy: row.Rate, Idempotency: row.Idempotency, EventSemantics: row.Events, HandlerOwner: row.Owners[0], Method: row.Method, Path: row.Path, OpenAPIOperationID: row.OpenAPIID}
}
