package i18n

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"text/template/parse"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
)

// Catalog is caller-owned construction input. Locale is canonical supported
// BCP 47, Version is positive and Messages contains 1..10000 unique IDs.
// NewCatalogStore/Replace freeze copies; do not mutate input during those calls.
type Catalog struct {
	Locale   string
	Version  uint64
	Messages []Message
}

// Message declares a bounded transport-neutral template and its exact typed
// placeholders. Templates are UTF-8, 1..8192 bytes, with at most 256 parts.
// The authoring language permits literal text and constant-string value,
// plural and select actions only; see README for the complete grammar.
type Message struct {
	ID           MessageID
	Template     string
	Placeholders []ParameterSpec
}

// Parameter retains an unescaped typed scalar and its declared output context.
// It has SafeParameter's bounds and sensitivity contract; final-context owners
// must escape/validate it appropriately, never as an arbitrary Stringer.
type Parameter struct {
	Name    string
	Value   identity.AttributeScalar
	Context ParameterContext
}

func (p Parameter) Format(s fmt.State, verb rune) { SafeParameter(p).Format(s, verb) }

// RenderPart is either trusted catalog literal text or one caller-owned typed
// parameter. Literal is empty when Parameter is present. This preserves value
// boundaries for final-context owners; it does not infer HTML/URL/header syntax.
type RenderPart struct {
	Literal   string
	Parameter *Parameter
}

func (RenderPart) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("i18n.RenderPart(redacted)")) }

// RenderedMessage is a caller-owned result from one immutable catalog version.
// Message is an unescaped display preview, not safe HTML, URL, header or JSON.
// Parts and Parameters preserve typed contexts; neither shares caller input or
// store state. Do not mutate results concurrently with their consumers.
type RenderedMessage struct {
	Locale     Locale
	Version    uint64
	Message    string
	Parameters []Parameter
	Parts      []RenderPart
}

func (RenderedMessage) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.RenderedMessage(redacted)"))
}

// CatalogConflictError means malformed, duplicate, incompatible or stale
// publication input; diagnostics never contain catalog/source text.
type CatalogConflictError struct{}

func (CatalogConflictError) Error() string { return "identity.i18n: catalog conflict" }

// MissingMessageError classifies absence of the exact locale/message pair.
// Render never silently substitutes a locale; the resolver owns fallback.
type MissingMessageError struct{}

func (MissingMessageError) Error() string { return "identity.i18n: missing message" }

// MissingParameterError means the supplied parameters do not exactly satisfy
// the declared schema, including missing, extra, mistyped or misplaced values.
type MissingParameterError struct{}

func (MissingParameterError) Error() string { return "identity.i18n: invalid message parameters" }

// RenderLimitError means the preview is empty or exceeds 8192 UTF-8 bytes.
// No partial preview, parameter collection or parts are returned on failure.
type RenderLimitError struct{}

func (RenderLimitError) Error() string { return "identity.i18n: invalid rendered size" }

type compiledPart struct {
	literal string
	name    string
	op      string
	choices map[string]string
}
type compiledMessage struct {
	schema []ParameterSpec
	parts  []compiledPart
}
type catalogSnapshot struct {
	version  uint64
	locales  []Locale
	messages map[Locale]map[MessageID]compiledMessage
}

// CatalogStore publishes complete immutable catalog snapshots using one atomic
// pointer. It has no goroutines or IO. Zero is invalid; do not copy a store.
// Concurrent Render/Locales/Replace calls are safe with immutable call inputs.
type CatalogStore struct {
	snapshot             atomic.Pointer[catalogSnapshot]
	publishMu            sync.Mutex // Owns publication and resolver admission constraints.
	admitted             map[MessageID][]ParameterSpec
	requiredLocales      map[Locale]bool
	requiredTranslations map[Locale]map[MessageID]bool
}

// NewCatalogStore validates/copies 1..256 distinct canonical locales with one
// common positive version. Across the snapshot there are at most 10000 messages
// and 8 MiB source bytes. Overlapping message IDs require identical placeholder
// sets/kinds/contexts across translations (declaration order may differ).
func NewCatalogStore(catalogs []Catalog) (*CatalogStore, error) {
	snapshot, err := compileCatalogs(catalogs)
	if err != nil {
		return nil, err
	}
	store := &CatalogStore{}
	store.snapshot.Store(snapshot)
	return store, nil
}

// Replace compiles a complete successor before publication. Exactly one caller
// with the expected current version can publish a strictly greater version.
// Failure leaves the old snapshot untouched; no automatic retry or merging is
// performed. Removed locales/messages become absent only after publication.
func (s *CatalogStore) Replace(expected uint64, catalogs []Catalog) error {
	if s == nil || expected == 0 {
		return CatalogConflictError{}
	}
	before := s.snapshot.Load()
	if before == nil || before.version != expected {
		return CatalogConflictError{}
	}
	after, err := compileCatalogs(catalogs)
	if err != nil {
		return err
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	if !validAdmission(after, s.admitted, s.requiredLocales, s.requiredTranslations) {
		return CatalogConflictError{}
	}
	if after.version <= expected || !s.snapshot.CompareAndSwap(before, after) {
		return CatalogConflictError{}
	}
	return nil
}

// Locales returns construction order and version from one snapshot, with an
// independent collection. Nil/zero stores return nil,0 and are not usable.
func (s *CatalogStore) Locales() ([]Locale, uint64) {
	if s == nil {
		return nil, 0
	}
	v := s.snapshot.Load()
	if v == nil {
		return nil, 0
	}
	return slices.Clone(v.locales), v.version
}

// Render validates exact parameters and renders one locale/message without
// fallback, escaping, persistence or error classification. It samples one
// snapshot, checks cancellation before each part and bounds preview allocation.
// Nil context/store fails; all errors return a zero result. Parameter callbacks,
// arbitrary functions, template methods and recursive template execution are
// impossible: compiled actions operate only on the closed scalar values.
func (s *CatalogStore) Render(ctx context.Context, locale Locale, id MessageID, parameters []Parameter) (RenderedMessage, error) {
	if ctx == nil || s == nil {
		return RenderedMessage{}, CatalogConflictError{}
	}
	if err := ctx.Err(); err != nil {
		return RenderedMessage{}, err
	}
	v := s.snapshot.Load()
	if v == nil {
		return RenderedMessage{}, CatalogConflictError{}
	}
	return renderSnapshot(ctx, v, locale, id, parameters)
}

// One already captured snapshot owns both resolver negotiation and rendering.
func renderSnapshot(ctx context.Context, v *catalogSnapshot, locale Locale, id MessageID, parameters []Parameter) (RenderedMessage, error) {
	// Validate caller-defined casts before hashing lookup keys, not merely
	// after failing to find them in the configured catalog.
	canonical, err := CanonicalLocale(string(locale))
	if err != nil || canonical != locale {
		return RenderedMessage{}, InvalidLocaleError{}
	}
	if !stableName(string(id), true) {
		return RenderedMessage{}, MissingMessageError{}
	}
	m, found := v.messages[locale][id]
	if !found {
		return RenderedMessage{}, MissingMessageError{}
	}
	if len(parameters) > 32 {
		return RenderedMessage{}, MissingParameterError{}
	}
	safe := make([]SafeParameter, len(parameters))
	for i, p := range parameters {
		safe[i] = SafeParameter(p)
	}
	ordered, valid := checkedParameters(m.schema, safe)
	if !valid {
		return RenderedMessage{}, MissingParameterError{}
	}
	byName := make(map[string]Parameter, len(ordered))
	var resultParams []Parameter
	for _, p := range ordered {
		value := Parameter(p)
		byName[value.Name] = value
		resultParams = append(resultParams, value)
	}
	var builder strings.Builder
	var parts []RenderPart
	tag, _ := language.Parse(string(locale)) // The frozen locale was strictly validated.
	for _, part := range m.parts {
		if err := ctx.Err(); err != nil {
			return RenderedMessage{}, err
		}
		text := part.literal
		output := RenderPart{Literal: text}
		if part.name != "" {
			value := byName[part.name]
			switch part.op {
			case "value":
				text = scalarText(value.Value)
				output = RenderPart{Parameter: &value}
			case "plural":
				key := "=" + strconv.FormatInt(value.Value.Int64, 10)
				var found bool
				text, found = part.choices[key]
				if !found {
					text, found = part.choices[pluralKey(tag, value.Value.Int64)]
				}
				if !found {
					text = part.choices["other"]
				}
				output.Literal = text
			case "select":
				key := scalarText(value.Value)
				var found bool
				text, found = part.choices[key]
				if !found {
					text = part.choices["other"]
				}
				output.Literal = text
			}
		}
		if len(text) > 8192-builder.Len() {
			return RenderedMessage{}, RenderLimitError{}
		}
		builder.WriteString(text)
		parts = append(parts, output)
	}
	if builder.Len() == 0 {
		return RenderedMessage{}, RenderLimitError{}
	}
	if err := ctx.Err(); err != nil {
		return RenderedMessage{}, err
	}
	return RenderedMessage{Locale: locale, Version: v.version, Message: builder.String(), Parameters: resultParams, Parts: parts}, nil
}

func compileCatalogs(catalogs []Catalog) (*catalogSnapshot, error) {
	bad := CatalogConflictError{}
	if len(catalogs) == 0 || len(catalogs) > 256 {
		return nil, bad
	}
	version := catalogs[0].Version
	if version == 0 {
		return nil, bad
	}
	count, bytes := 0, 0
	for _, c := range catalogs {
		if c.Version != version || len(c.Messages) == 0 || len(c.Messages) > 10000-count {
			return nil, bad
		}
		count += len(c.Messages)
		for _, m := range c.Messages {
			if len(m.Template) > 8*1024*1024-bytes {
				return nil, bad
			}
			bytes += len(m.Template)
		}
	}
	snapshot := &catalogSnapshot{version: version, messages: make(map[Locale]map[MessageID]compiledMessage, len(catalogs))}
	schemas := make(map[MessageID][]ParameterSpec, count)
	for _, c := range catalogs {
		locale, err := CanonicalLocale(c.Locale)
		if err != nil || string(locale) != c.Locale || snapshot.messages[locale] != nil {
			return nil, bad
		}
		messages := make(map[MessageID]compiledMessage, len(c.Messages))
		for _, m := range c.Messages {
			if !stableName(string(m.ID), true) {
				return nil, bad
			}
			if _, exists := messages[m.ID]; exists {
				return nil, bad
			}
			compiled, err := compileMessage(m)
			if err != nil {
				return nil, err
			}
			ordered := slices.Clone(compiled.schema)
			slices.SortFunc(ordered, func(a, b ParameterSpec) int { return strings.Compare(a.Name, b.Name) })
			if previous, exists := schemas[m.ID]; exists && !slices.Equal(previous, ordered) {
				return nil, bad
			}
			schemas[m.ID] = ordered
			messages[m.ID] = compiled
		}
		snapshot.messages[locale] = messages
		snapshot.locales = append(snapshot.locales, locale)
	}
	return snapshot, nil
}

func compileMessage(message Message) (compiledMessage, error) {
	bad := CatalogConflictError{}
	if len(message.Template) == 0 || len(message.Template) > 8192 || !utf8.ValidString(message.Template) || !validSchema(message.Placeholders) {
		return compiledMessage{}, bad
	}
	// These names only authorize parsing. Execute is never called, and every
	// AST node/argument is checked below before becoming a closed compiled part.
	placeholder := func(...string) string { return "" }
	parsed, err := template.New("message").Funcs(template.FuncMap{"value": placeholder, "plural": placeholder, "select": placeholder}).Parse(message.Template)
	if err != nil || len(parsed.Templates()) != 1 || parsed.Tree == nil || parsed.Tree.Root.Position() != 0 || len(parsed.Tree.Root.Nodes) == 0 || len(parsed.Tree.Root.Nodes) > 256 {
		return compiledMessage{}, bad
	}
	byName := make(map[string]ParameterSpec, len(message.Placeholders))
	for _, spec := range message.Placeholders {
		byName[spec.Name] = spec
	}
	used := make(map[string]bool, len(message.Placeholders))
	compiled := compiledMessage{schema: slices.Clone(message.Placeholders)}
	for _, node := range parsed.Tree.Root.Nodes {
		if literal, ok := node.(*parse.TextNode); ok {
			compiled.parts = append(compiled.parts, compiledPart{literal: string(literal.Text)})
			continue
		}
		action, ok := node.(*parse.ActionNode)
		if !ok || len(action.Pipe.Decl) != 0 || len(action.Pipe.Cmds) != 1 {
			return compiledMessage{}, bad
		}
		args := action.Pipe.Cmds[0].Args
		if len(args) < 2 || len(args) > 34 {
			return compiledMessage{}, bad
		}
		function, ok := args[0].(*parse.IdentifierNode)
		if !ok {
			return compiledMessage{}, bad
		}
		var values []string
		for _, arg := range args[1:] {
			value, ok := arg.(*parse.StringNode)
			if !ok || !utf8.ValidString(value.Text) {
				return compiledMessage{}, bad
			}
			values = append(values, value.Text)
		}
		spec, exists := byName[values[0]]
		if !exists {
			return compiledMessage{}, bad
		}
		part := compiledPart{name: spec.Name, op: function.Ident}
		switch function.Ident {
		case "value":
			if len(values) != 2 || ParameterContext(values[1]) != spec.Context {
				return compiledMessage{}, bad
			}
		case "plural", "select":
			if len(values) < 3 || len(values)%2 != 1 || len(values) > 33 || function.Ident == "plural" && spec.Kind != identity.AttributeInt64 || function.Ident == "select" && spec.Kind != identity.AttributeString && spec.Kind != identity.AttributeBool {
				return compiledMessage{}, bad
			}
			part.choices = make(map[string]string, (len(values)-1)/2)
			for i := 1; i < len(values); i += 2 {
				key := values[i]
				if len(key) == 0 || len(key) > 128 || function.Ident == "plural" && !validPluralKey(key) || function.Ident == "select" && spec.Kind == identity.AttributeBool && key != "true" && key != "false" && key != "other" {
					return compiledMessage{}, bad
				}
				if _, duplicate := part.choices[key]; duplicate {
					return compiledMessage{}, bad
				}
				part.choices[key] = values[i+1]
			}
			if _, present := part.choices["other"]; !present {
				return compiledMessage{}, bad
			}
		default:
			return compiledMessage{}, bad
		}
		used[spec.Name] = true
		compiled.parts = append(compiled.parts, part)
	}
	if len(used) != len(byName) {
		return compiledMessage{}, bad
	}
	return compiled, nil
}

func validPluralKey(key string) bool {
	switch key {
	case "zero", "one", "two", "few", "many", "other":
		return true
	}
	if !strings.HasPrefix(key, "=") {
		return false
	}
	n, err := strconv.ParseInt(key[1:], 10, 64)
	return err == nil && strconv.FormatInt(n, 10) == key[1:]
}

func scalarText(value identity.AttributeScalar) string {
	switch value.Kind {
	case identity.AttributeString:
		return value.String
	case identity.AttributeBool:
		return strconv.FormatBool(value.Bool)
	case identity.AttributeInt64:
		return strconv.FormatInt(value.Int64, 10)
	case identity.AttributeTime:
		return value.Time.UTC().Format(time.RFC3339Nano)
	}
	return "" // Only checkedParameters-approved scalar kinds reach rendering.
}

func pluralKey(tag language.Tag, number int64) string {
	magnitude := uint64(number)
	if number < 0 {
		// Negating MinInt64 directly overflows; take the last unit unsigned.
		magnitude = uint64(-(number + 1)) + 1
	}
	// MatchPlural documents a 10,000,000 modulus for oversized operands.
	// Retain a large-number sentinel as well as the suffix: plain modulo
	// would turn English 10,000,001 into the exact singular operand 1.
	// The representative fits even a 32-bit int and retains the pinned
	// rules' modulo tests without triggering their small-number exceptions.
	const modulus = 10_000_000
	if magnitude >= modulus {
		magnitude = modulus + magnitude%modulus
	}
	form := plural.Cardinal.MatchPlural(tag, int(magnitude), 0, 0, 0, 0)
	return [...]string{"other", "zero", "one", "two", "few", "many"}[form]
}
