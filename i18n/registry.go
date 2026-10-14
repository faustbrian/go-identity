package i18n

import (
	"fmt"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// ErrorIdentity is a stable owning-package machine identity, never Error text.
// It is 1..128 lowercase ASCII bytes, starts with a letter and thereafter uses
// letters, digits, dot, hyphen or underscore. Casting does not validate it.
type ErrorIdentity string

// MessageID identifies a catalog message independently of locale or rendering.
// It follows the same bounded syntax as ErrorIdentity; zero is invalid.
type MessageID string

// ParameterContext declares the final output context without escaping values.
// The final delivery/HTTP owner must apply context-specific escaping once.
type ParameterContext string

const (
	ParameterPlainText ParameterContext = "plain-text"
	ParameterURL       ParameterContext = "url"
	ParameterHeader    ParameterContext = "header"
	ParameterJSON      ParameterContext = "json"
	ParameterHTML      ParameterContext = "html"
)

// ParameterSpec declares an exact scalar kind and output context. Name uses
// 1..128 lowercase ASCII letters/digits/underscores, starting with a letter.
// Lists, floats, arbitrary objects and unspecified contexts are unsupported.
type ParameterSpec struct {
	Name    string
	Kind    identity.AttributeKind
	Context ParameterContext
}

// ParameterSchema declares up to 32 ordered, uniquely named safe parameters.
// Registration copies its collection; nil explicitly means no parameters.
type ParameterSchema struct {
	Parameters []ParameterSpec
}

// SafeParameter is an explicitly public, typed, unescaped value. The domain
// error owner must never supply credentials, raw diagnostics or enumeration
// state. Schema validation proves shape, not the meaning/sensitivity of text.
// Strings are UTF-8 and at most 4096 bytes; only the selected scalar arm may
// be populated. Empty strings, false and integer zero are valid values.
type SafeParameter struct {
	Name    string
	Value   identity.AttributeScalar
	Context ParameterContext
}

// Format keeps even safe personal values out of ordinary diagnostics.
func (SafeParameter) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.SafeParameter(redacted)"))
}

// LocalizableError is implemented by the owning domain error, not a string
// classifier. Methods must be bounded and return immutable/caller-owned values.
// Resolver reads never call Error or custom As; wrappers may expose Unwrap.
type LocalizableError interface {
	ErrorIdentity() ErrorIdentity
	SafeParameters() []SafeParameter
}

// RegistryConflictError classifies malformed, duplicate or post-seal
// registrations without exposing names, schemas or caller error diagnostics.
type RegistryConflictError struct{}

func (RegistryConflictError) Error() string { return "identity.i18n: registry conflict" }

type errorRegistration struct {
	message MessageID
	schema  []ParameterSpec
}

type registryState struct {
	mu      sync.RWMutex // Owns construction/sealing and the immutable map.
	sealed  bool
	entries map[ErrorIdentity]errorRegistration
}

// ErrorRegistry has one shared build/seal lifetime across copies. Zero is
// invalid. Register is construction-only; sealed Resolve is concurrent-safe.
// Methods never hold a lock across error-owner or Unwrap callbacks.
type ErrorRegistry struct {
	state *registryState
}

// NewErrorRegistry constructs an empty unsealed registry. The owning packages
// register their identities once, then SealErrorRegistry (or the resolver
// constructor) freezes it before use. At most 10000 registrations are allowed.
func NewErrorRegistry() *ErrorRegistry {
	return &ErrorRegistry{state: &registryState{entries: make(map[ErrorIdentity]errorRegistration)}}
}

// Register copies one exact declaration. Duplicate identities fail even for
// byte-identical declarations: they do not establish a second owning package.
// Construction is synchronized; concurrent duplicate registration has one winner.
// Callers must not mutate schema.Parameters during the call.
func (r *ErrorRegistry) Register(id ErrorIdentity, message MessageID, schema ParameterSchema) error {
	if r == nil || r.state == nil || !stableName(string(id), true) || !stableName(string(message), true) || !validSchema(schema.Parameters) {
		return RegistryConflictError{}
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.sealed || len(r.state.entries) >= 10000 {
		return RegistryConflictError{}
	}
	if _, exists := r.state.entries[id]; exists {
		return RegistryConflictError{}
	}
	r.state.entries[id] = errorRegistration{message: message, schema: slices.Clone(schema.Parameters)}
	return nil
}

// SealErrorRegistry freezes the shared registry lifetime, idempotently. It
// cannot be reopened. Resolve before sealing returns false; sealing an invalid
// zero/nil registry fails. This also supports typed registry consumers without
// requiring catalog rendering; NewConfiguredResolver seals the same lifetime after
// validating catalog/schema admission.
func SealErrorRegistry(r *ErrorRegistry) error {
	if r == nil || r.state == nil {
		return RegistryConflictError{}
	}
	r.state.mu.Lock()
	r.state.sealed = true
	r.state.mu.Unlock()
	return nil
}

// Resolve returns a schema-ordered caller-owned copy only for a registered
// LocalizableError with exact safe values. It never renders or inspects Error
// text. Unknown identity, malformed values, unsealed/zero registry or panic
// returns zero/false without changing the original error. Wrapped/joined errors
// are visited depth-first left-to-right, at most 32 nodes; the first typed
// identity controls the result, so invalid/unknown typed wrappers cannot expose
// an inner translation accidentally. Cyclic/oversized wrappers fail closed.
// A callback must obey LocalizableError's bounded-work contract; this function
// cannot cancel arbitrary caller code and creates no background goroutines.
func (r *ErrorRegistry) Resolve(err error) (message MessageID, parameters []SafeParameter, ok bool) {
	_, message, parameters, ok = r.resolveRegistered(err)
	return
}

// resolveRegistered captures the owning identity in the same traversal as the
// parameters; rendering must not call a mutable domain callback twice.
func (r *ErrorRegistry) resolveRegistered(err error) (id ErrorIdentity, message MessageID, parameters []SafeParameter, ok bool) {
	defer func() {
		if recover() != nil {
			id, message, parameters, ok = "", "", nil, false
		}
	}()
	if r == nil || r.state == nil || err == nil {
		return "", "", nil, false
	}
	r.state.mu.RLock()
	sealed := r.state.sealed
	r.state.mu.RUnlock()
	if !sealed {
		return "", "", nil, false
	}
	stack := []error{err}
	for visits := 0; len(stack) != 0 && visits < 32; visits++ {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == nil {
			continue
		}
		if typed, found := current.(LocalizableError); found {
			id := typed.ErrorIdentity()
			if !stableName(string(id), true) {
				return "", "", nil, false
			}
			r.state.mu.RLock()
			registration, registered := r.state.entries[id]
			r.state.mu.RUnlock()
			if !registered {
				return "", "", nil, false
			}
			values, valid := checkedParameters(registration.schema, typed.SafeParameters())
			if !valid {
				return "", "", nil, false
			}
			return id, registration.message, values, true
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			if len(children) > 32-len(stack)-visits-1 {
				return "", "", nil, false
			}
			for i := len(children) - 1; i >= 0; i-- {
				stack = append(stack, children[i])
			}
		case interface{ Unwrap() error }:
			stack = append(stack, wrapped.Unwrap())
		}
	}
	return "", "", nil, false
}

func stableName(name string, punctuation bool) bool {
	if len(name) == 0 || len(name) > 128 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || punctuation && (c == '.' || c == '-')) {
			return false
		}
	}
	return true
}

func validContext(context ParameterContext) bool {
	return context == ParameterPlainText || context == ParameterURL || context == ParameterHeader || context == ParameterJSON || context == ParameterHTML
}

func validSchema(parameters []ParameterSpec) bool {
	if len(parameters) > 32 {
		return false
	}
	seen := make(map[string]bool, len(parameters))
	for _, spec := range parameters {
		if !stableName(spec.Name, false) || seen[spec.Name] || !validContext(spec.Context) || spec.Kind != identity.AttributeString && spec.Kind != identity.AttributeBool && spec.Kind != identity.AttributeInt64 && spec.Kind != identity.AttributeTime {
			return false
		}
		seen[spec.Name] = true
	}
	return true
}

func checkedParameters(schema []ParameterSpec, input []SafeParameter) ([]SafeParameter, bool) {
	if len(input) != len(schema) || len(input) > 32 {
		return nil, false
	}
	byName := make(map[string]SafeParameter, len(input))
	for _, value := range input {
		if !stableName(value.Name, false) {
			return nil, false
		}
		if _, exists := byName[value.Name]; exists || !validScalar(value.Value) {
			return nil, false
		}
		byName[value.Name] = value
	}
	var output []SafeParameter
	for _, spec := range schema {
		value, found := byName[spec.Name]
		if !found || value.Value.Kind != spec.Kind || value.Context != spec.Context {
			return nil, false
		}
		output = append(output, value)
	}
	return output, true
}

func validScalar(value identity.AttributeScalar) bool {
	switch value.Kind {
	case identity.AttributeString:
		return len(value.String) <= 4096 && utf8.ValidString(value.String) && !value.Bool && value.Int64 == 0 && value.Time == (time.Time{})
	case identity.AttributeBool:
		return value.String == "" && value.Int64 == 0 && value.Time == (time.Time{})
	case identity.AttributeInt64:
		return value.String == "" && !value.Bool && value.Time == (time.Time{})
	case identity.AttributeTime:
		return value.String == "" && !value.Bool && value.Int64 == 0 && !value.Time.IsZero()
	default:
		return false
	}
}
