package identityhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/reference"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// WireComponent is one concrete JSON Schema or Security Scheme Object. Name
// is a 1..128-byte component identifier. Definition is strict bounded JSON;
// references must be internal. Feature owners supply public, non-secret data.
// Inputs must not be mutated concurrently with construction.
type WireComponent struct {
	Name       string
	Definition []byte
}

// WireOperation contains the actual OpenAPI Operation Object, separate from
// direct Go-contract identities. Definition is 1..64KiB, schemas/security each
// contain at most 64 components of 1..64KiB, and aggregate size is <=512KiB.
// Schemas and schemes are globally unique, including identical duplicates.
// Declare shared components once and refer to them from other operations.
// Factories own correspondence with their real handlers; validation cannot
// prove arbitrary caller handlers enforce a schema or security declaration.
type WireOperation struct {
	Definition               []byte
	Schemas, SecuritySchemes []WireComponent
}

// DocumentConfig contains static public document identity, not runtime hosts,
// credentials, tenant names or provider configuration. Both strings are
// printable ASCII (title 1..128, version 1..64). No server URL is inferred.
type DocumentConfig struct{ Title, Version string }

// OpenAPIDocument owns deterministic validated 3.1.1 JSON and the matching
// selected operation snapshot. Zero has no document. No endpoint is registered
// implicitly. Metadata exports do not confer authentication or authority.
type OpenAPIDocument struct {
	data       []byte
	operations []OperationDescriptor
	coverage   []OperationCoverage
}

// JSON returns detached document bytes; callers own the returned storage.
func (d OpenAPIDocument) JSON() []byte { return slices.Clone(d.data) }

// Operations returns detached matching metadata, borrowing only handlers.
func (d OpenAPIDocument) Operations() []OperationDescriptor { return cloneOperations(d.operations) }

// Version returns exactly 3.1.1, or empty for a zero document.
func (d OpenAPIDocument) Version() string {
	if len(d.data) == 0 {
		return ""
	}
	return "3.1.1"
}

// Digest identifies the exact exported JSON snapshot; zero returns zero.
// This content identity is not a signature, authority or release certificate.
func (d OpenAPIDocument) Digest() [32]byte {
	if len(d.data) == 0 {
		return [32]byte{}
	}
	return sha256.Sum256(d.data)
}

// Schemas returns detached named wire components in name order. Inline schemas
// remain in JSON; canonical direct-contract summaries are deliberately excluded.
func (d OpenAPIDocument) Schemas() []WireComponent {
	var schemas []WireComponent
	for _, op := range d.operations {
		if op.Wire != nil {
			for _, c := range op.Wire.Schemas {
				schemas = append(schemas, WireComponent{Name: c.Name, Definition: slices.Clone(c.Definition)})
			}
		}
	}
	slices.SortFunc(schemas, func(a, b WireComponent) int { return strings.Compare(a.Name, b.Name) })
	return schemas
}

// NewDocumentedHandler freezes exact selected dispatch and concrete OpenAPI
// from the same immutable feature selection. Every selected route must supply
// its real wire definition; direct summaries are never rendered as schemas.
// Invalid/missing definitions, duplicate components, unresolved/external
// references or normative validation failures return no partial result.
// Empty selection has empty paths/components and no advertised capabilities.
//
// Construction invokes no handlers, stores, clocks or network IO. The owned
// OpenAPI engine applies bounded strict parsing and normative/schema validation;
// a five-second construction budget never extends ctx. Nil/canceled ctx denies.
// Canonical dotted operation IDs are retained even though the OpenAPI owner
// advises portable programming identifiers; generated clients must map them.
// All other validation diagnostics deny, and a saturated diagnostic budget
// denies rather than allowing truncation to hide errors. Schema references use
// internal JSON pointers only; externalValue, $id and $dynamicRef are excluded
// from this self-contained profile. Errors redact descriptions and schema
// diagnostics. The 16MiB document cap,
// depth64 and finite node/component limits apply before unbounded allocation.
// Inputs must not change during construction; exports and dispatch are safe for
// concurrent use. This does not replace the complete NewRouter/security-policy
// builder: existing real feature handlers retain enforcement and bounded IO.
func NewDocumentedHandler(ctx context.Context, config DocumentConfig, services FeatureServices) (http.Handler, OpenAPIDocument, error) {
	if ctx == nil || !ascii(config.Title, 128, true) || !ascii(config.Version, 64, true) {
		return nil, OpenAPIDocument{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, OpenAPIDocument{}, err
	}
	ops, err := NewOperationDescriptors(services)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	paths, schemas, security := map[string]any{}, map[string]any{}, map[string]any{}
	for _, op := range ops {
		if op.Wire == nil {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
		definition, err := wireObject(ctx, op.Wire.Definition)
		if err != nil || definition["operationId"] != op.Record.OpenAPIOperationID || definition["servers"] != nil || definition["x-identity-policy"] != nil {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
		definition["x-identity-policy"] = map[string]any{"operation": op.Record.OperationID, "owner": op.Record.HandlerOwner, "access": op.Record.Access, "rate": op.Record.RatePolicy, "idempotency": op.Record.Idempotency}
		path, ok := paths[op.Route.Path].(map[string]any)
		if !ok {
			path = map[string]any{}
			paths[op.Route.Path] = path
		}
		path[strings.ToLower(op.Route.Method)] = definition
		for i, components := range [][]WireComponent{op.Wire.Schemas, op.Wire.SecuritySchemes} {
			target := schemas
			if i == 1 {
				target = security
			}
			for _, c := range components {
				if _, exists := target[c.Name]; exists {
					return nil, OpenAPIDocument{}, ErrInvalidInput
				}
				var value any
				var err error
				if i == 0 {
					value, err = wireValue(ctx, c.Definition)
				} else {
					value, err = wireObject(ctx, c.Definition)
				}
				if err != nil {
					return nil, OpenAPIDocument{}, ErrInvalidInput
				}
				target[c.Name] = value
			}
		}
	}
	root := map[string]any{"openapi": "3.1.1", "info": map[string]any{"title": config.Title, "version": config.Version}, "paths": paths, "components": map[string]any{"schemas": schemas, "securitySchemes": security}}
	data, err := json.Marshal(root)
	if err != nil || len(data) > 16<<20 {
		return nil, OpenAPIDocument{}, ErrInvalidInput
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(data), wireLimits(16<<20))
	if err != nil {
		return nil, OpenAPIDocument{}, wireError(ctx)
	}
	profile := wireProfile{ctx: ctx, document: parsed}
	if err := profile.walk(parsed.Raw(), "document"); err != nil {
		return nil, OpenAPIDocument{}, wireError(ctx)
	}
	// A reference can make otherwise opaque extension data a Response, Header,
	// Callback or other structural object. Validate the owner's bounded resolved
	// view as well; validating only the original Reference Object would not check
	// the target's required fields. Preserve original snapshot bytes for export.
	dereference := reference.DefaultDereferenceOptions()
	dereference.MaxReferences, dereference.MaxNodes, dereference.MaxDepth = 8192, 200000, 64
	dereference.ReferenceLimits = reference.Limits{MaxTraversalNodes: 200000, MaxTraversalDepth: 64, MaxReferenceDepth: 64}
	resolved, err := reference.DereferenceObjects(ctx, reference.Resource{Root: parsed.Raw()}, nil, dereference)
	if err != nil {
		return nil, OpenAPIDocument{}, wireError(ctx)
	}
	options := validate.DefaultOptions()
	options.MaxDiagnostics = 8192
	options.MaxDocumentDepth = 64
	options.MaxDocumentNodes = 200000
	options.MaxReferences = 8192
	options.ReferenceResourceURI = "https://identity.invalid/openapi.json"
	report, err := validate.DocumentWithOptions(ctx, resolved.Document(), options)
	if err != nil || !report.Valid() || len(report.Diagnostics()) >= options.MaxDiagnostics {
		return nil, OpenAPIDocument{}, wireError(ctx)
	}
	for _, diagnostic := range report.Diagnostics() {
		if diagnostic.Severity != validate.SeverityWarning || diagnostic.Code != "openapi.operation-id.nonportable" {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
	}
	// Reconstruct only from our frozen descriptors; no second caller-owned
	// selection read can diverge the document from the routed snapshot.
	handler, err := selectedHandler(ops)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	return handler, OpenAPIDocument{data: data, operations: ops, coverage: documentCoverage(ops)}, nil
}

func wireError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrInvalidInput
}
func wireLimits(maxBytes int64) parse.Limits {
	l := parse.DefaultLimits()
	l.MaxBytes = maxBytes
	l.MaxDepth = 64
	l.MaxTotalValues = 200000
	l.MaxTokens = 400000
	l.MaxObjectMembers = 8192
	l.MaxArrayItems = 8192
	l.MaxScalarBytes = 65536
	return l
}
func wireObject(ctx context.Context, data []byte) (map[string]any, error) {
	value, err := wireValue(ctx, data)
	object, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, ErrInvalidInput
	}
	return object, nil
}

func wireValue(ctx context.Context, data []byte) (any, error) {
	value, err := parse.JSON(ctx, bytes.NewReader(data), wireLimits(65536))
	if err != nil {
		return nil, ErrInvalidInput
	}
	encoded, err := value.MarshalJSON()
	if err != nil {
		return nil, ErrInvalidInput
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, ErrInvalidInput
	}
	if _, ok := object.(map[string]any); !ok {
		if _, ok := object.(bool); !ok {
			return nil, ErrInvalidInput
		}
	}
	return object, nil
}

func wireSize(w *WireOperation) int {
	if w == nil {
		return 0
	}
	n := len(w.Definition)
	for _, cs := range [][]WireComponent{w.Schemas, w.SecuritySchemes} {
		for _, c := range cs {
			n += len(c.Name) + len(c.Definition)
		}
	}
	return n
}
func validWireBounds(w *WireOperation) bool {
	if w == nil {
		return true
	}
	if len(w.Definition) < 1 || len(w.Definition) > 65536 || len(w.Schemas) > 64 || len(w.SecuritySchemes) > 64 {
		return false
	}
	for _, cs := range [][]WireComponent{w.Schemas, w.SecuritySchemes} {
		for _, c := range cs {
			if !identifier(c.Name, 128) || len(c.Definition) < 1 || len(c.Definition) > 65536 {
				return false
			}
		}
	}
	return wireSize(w) <= 512<<10
}
func cloneWire(w *WireOperation) *WireOperation {
	if w == nil {
		return nil
	}
	result := *w
	result.Definition = slices.Clone(w.Definition)
	copyComponents := func(input []WireComponent) []WireComponent {
		output := slices.Clone(input)
		for i := range output {
			output[i].Definition = slices.Clone(output[i].Definition)
		}
		return output
	}
	result.Schemas = copyComponents(w.Schemas)
	result.SecuritySchemes = copyComponents(w.SecuritySchemes)
	return &result
}
