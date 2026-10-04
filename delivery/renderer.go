package delivery

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

// VariableSchema fixes each required variable's kind and sensitivity. A message
// must match exactly; neither missing variables nor undeclared extras are allowed.
type VariableSchema struct {
	Name      string
	Kind      string
	Sensitive bool
}

// Template is an immutable versioned channel/locale declaration. The current
// renderer supports text/plain and text/html with literal text and {{.name}}
// substitutions only: no functions, loops, nested lookups or dynamic templates.
// HTML uses a non-active email vocabulary; scripts/styles/events are rejected.
// Sources are each bounded to262144 UTF-8 bytes (subject998); schema64, origins32.
// MaxRenderedBytes bounds subject plus body, up to262144 bytes. URLs must use an
// exact declared HTTPS origin, independent of whether they occur in subject/body.
type Template struct {
	ID                string
	Version           uint64
	Channel           Channel
	Locale            string
	RequiredVariables []string
	MaxRenderedBytes  uint32
	Subject           string
	Body              string
	ContentType       string
	VariableSchema    []VariableSchema
	AllowedOrigins    []string
}

// RenderedMessage is sensitive transport content. Plain text is not HTML escaped.
// Explicit fields are for the queue/sender boundary, not diagnostics or retention.
type RenderedMessage struct {
	Channel     Channel
	Locale      string
	Subject     string
	Body        string
	ContentType string
}

// Renderer owns deterministic version/channel/locale selection and final-context
// escaping. It neither negotiates user locale nor enqueues or delivers messages.
type Renderer interface {
	Render(context.Context, Message) (RenderedMessage, error)
}

type templateKey struct {
	id      string
	version uint64
	channel Channel
	locale  string
}
type segment struct {
	text, variable string
	escape         bool
}
type compiledTemplate struct {
	key           templateKey
	subject, body []segment
	schema        map[string]VariableSchema
	origins       map[string]bool
	limit         int
	contentType   string
}

// TemplateRenderer retains only a validated immutable catalog. Concurrent Render
// calls are safe; caller inputs must not mutate during a call. No goroutines,
// network operations or callbacks are used; output allocation is bounded.
type TemplateRenderer struct {
	catalog map[templateKey]compiledTemplate
}

// NewTemplateRenderer validates and copies1..256 unique version/channel/locale
// templates. There is no implicit locale or version fallback outside LocaleChain.
// Invalid declarations fail with the redacted ErrInvalidInput, never source text.
func NewTemplateRenderer(templates []Template) (*TemplateRenderer, error) {
	if len(templates) == 0 || len(templates) > 256 {
		return nil, ErrInvalidInput
	}
	r := &TemplateRenderer{catalog: make(map[templateKey]compiledTemplate, len(templates))}
	for _, t := range templates {
		if !printableASCII(t.ID, 1, 128) || t.Version == 0 || !validChannel(t.Channel) || !localeShape(t.Locale) || (t.ContentType != "text/plain" && t.ContentType != "text/html") || !boundedText(t.Subject, 0, 998) || !boundedText(t.Body, 1, 262144) || t.MaxRenderedBytes == 0 || t.MaxRenderedBytes > 262144 || len(t.RequiredVariables) > 64 || len(t.VariableSchema) != len(t.RequiredVariables) || len(t.AllowedOrigins) > 32 || t.Channel == ChannelSMS && (t.Subject != "" || t.ContentType != "text/plain") {
			return nil, ErrInvalidInput
		}
		c := compiledTemplate{key: templateKey{t.ID, t.Version, t.Channel, t.Locale}, schema: make(map[string]VariableSchema), origins: make(map[string]bool), limit: int(t.MaxRenderedBytes), contentType: t.ContentType}
		if _, duplicate := r.catalog[c.key]; duplicate {
			return nil, ErrInvalidInput
		}
		required := make(map[string]bool)
		for _, name := range t.RequiredVariables {
			if !variableName(name) || required[name] {
				return nil, ErrInvalidInput
			}
			required[name] = true
		}
		for _, s := range t.VariableSchema {
			if !required[s.Name] || (s.Kind != "text" && s.Kind != "url" && s.Kind != "code" && s.Kind != "timestamp") {
				return nil, ErrInvalidInput
			}
			if _, exists := c.schema[s.Name]; exists {
				return nil, ErrInvalidInput
			}
			c.schema[s.Name] = s
		}
		for _, origin := range t.AllowedOrigins {
			if (TemplateVariable{Name: "origin", Kind: "url", URLValue: origin}).Validate() != nil {
				return nil, ErrInvalidInput
			}
			u, _ := url.Parse(origin)
			if u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
				return nil, ErrInvalidInput
			}
			key := originKey(u)
			if c.origins[key] {
				return nil, ErrInvalidInput
			}
			c.origins[key] = true
		}
		for _, s := range c.schema {
			if s.Kind == "url" && len(c.origins) == 0 {
				return nil, ErrInvalidInput
			}
		}
		var err error
		if c.subject, err = compileText(t.Subject, c.schema); err != nil {
			return nil, err
		}
		if t.ContentType == "text/html" {
			c.body, err = compileHTML(t.Body, c.schema, c.origins)
		} else {
			c.body, err = compileText(t.Body, c.schema)
		}
		if err != nil {
			return nil, err
		}
		r.catalog[c.key] = c
	}
	return r, nil
}

func originKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// Only a closed non-executable subset is retained; the standard parser never
// executes input, and its source-bearing errors never cross the public boundary.
func compileText(source string, schema map[string]VariableSchema) ([]segment, error) {
	out, err := compileSegments(source, schema)
	if err != nil {
		return nil, err
	}
	if err := checkPlainURLs(out, schema); err != nil {
		return nil, err
	}
	return out, nil
}

func compileSegments(source string, schema map[string]VariableSchema) ([]segment, error) {
	t, err := template.New("message").Parse(source)
	if err != nil || len(t.Templates()) != 1 {
		return nil, ErrInvalidInput
	}
	out := make([]segment, 0, len(t.Tree.Root.Nodes))
	for _, node := range t.Tree.Root.Nodes {
		switch n := node.(type) {
		case *parse.TextNode:
			out = append(out, segment{text: string(n.Text)})
		case *parse.ActionNode:
			if len(n.Pipe.Decl) != 0 || len(n.Pipe.Cmds) != 1 || len(n.Pipe.Cmds[0].Args) != 1 {
				return nil, ErrInvalidInput
			}
			field, ok := n.Pipe.Cmds[0].Args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 {
				return nil, ErrInvalidInput
			}
			if _, ok := schema[field.Ident[0]]; !ok {
				return nil, ErrInvalidInput
			}
			out = append(out, segment{variable: field.Ident[0]})
		default:
			return nil, ErrInvalidInput
		}
	}
	return out, nil
}

func checkPlainURLs(out []segment, schema map[string]VariableSchema) error {
	// Plain-text URLs must occupy an entire whitespace-delimited token. Otherwise
	// authorized inputs can become a different host when concatenated with either
	// template literals or another variable, before a mail client linkifies them.
	for i, part := range out {
		if part.variable == "" || schema[part.variable].Kind != "url" {
			continue
		}
		if i > 0 && (out[i-1].variable != "" || out[i-1].text == "" || !plainSpace(out[i-1].text[len(out[i-1].text)-1])) {
			return ErrInvalidInput
		}
		if i+1 < len(out) && (out[i+1].variable != "" || out[i+1].text == "" || !plainSpace(out[i+1].text[0])) {
			return ErrInvalidInput
		}
	}
	return nil
}

func plainSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

// Render validates exact schema/origins before rendering. Subject controls are
// forbidden after substitution; plain body text is preserved, HTML substitutions
// are escaped in the compiled final context. The combined
// byte bound is checked before each append, and cancellation between segments.
// Errors reveal no recipient, template source, variable content or availability.
func (r *TemplateRenderer) Render(ctx context.Context, m Message) (RenderedMessage, error) {
	if ctx == nil {
		return RenderedMessage{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return RenderedMessage{}, err
	}
	if r == nil || m.Validate() != nil {
		return RenderedMessage{}, ErrInvalidInput
	}
	var c compiledTemplate
	found := false
	for _, locale := range m.LocaleChain {
		if c, found = r.catalog[templateKey{m.TemplateID, m.TemplateVersion, m.Channel, locale}]; found {
			break
		}
	}
	if !found || len(m.Variables) != len(c.schema) {
		return RenderedMessage{}, ErrInvalidInput
	}
	values := make(map[string]string, len(m.Variables))
	for _, v := range m.Variables {
		s, ok := c.schema[v.Name]
		if !ok || s.Kind != v.Kind || s.Sensitive != v.Sensitive {
			return RenderedMessage{}, ErrInvalidInput
		}
		var value string
		switch v.Kind {
		case "text":
			value = v.TextValue
		case "code":
			value = v.CodeValue
		case "timestamp":
			value = v.TimeValue.UTC().Format(time.RFC3339Nano)
		case "url":
			u, _ := url.Parse(v.URLValue)
			if !c.origins[originKey(u)] {
				return RenderedMessage{}, ErrInvalidInput
			}
			value = v.URLValue
		}
		values[v.Name] = value
	}
	subject, err := renderSegments(ctx, c.subject, values, min(c.limit, 998))
	if err != nil {
		return RenderedMessage{}, err
	}
	for _, ch := range subject {
		if ch < 0x20 || ch == 0x7f {
			return RenderedMessage{}, ErrInvalidInput
		}
	}
	body, err := renderSegments(ctx, c.body, values, c.limit-len(subject))
	if err != nil {
		return RenderedMessage{}, err
	}
	if body == "" {
		return RenderedMessage{}, ErrInvalidInput
	}
	return RenderedMessage{Channel: m.Channel, Locale: c.key.locale, Subject: subject, Body: body, ContentType: c.contentType}, nil
}

func renderSegments(ctx context.Context, parts []segment, values map[string]string, limit int) (string, error) {
	var out strings.Builder
	for _, part := range parts {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		s := part.text
		if part.variable != "" {
			s = values[part.variable]
			if part.escape {
				s = html.EscapeString(s)
			}
		}
		if len(s) > limit-out.Len() {
			return "", ErrInvalidInput
		}
		out.WriteString(s)
	}
	return out.String(), nil
}

// Format suppresses template sources and sensitive rendered output for all verbs.
func (Template) Format(s fmt.State, _ rune)         { redact(s) }
func (RenderedMessage) Format(s fmt.State, _ rune)  { redact(s) }
func (TemplateRenderer) Format(s fmt.State, _ rune) { redact(s) }

// LogValue suppresses template and rendered content in structured diagnostics.
func (Template) LogValue() slog.Value        { return slog.StringValue("delivery(redacted)") }
func (RenderedMessage) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// MarshalJSON refuses implicit content serialization; explicit queue custody is required.
func (Template) MarshalJSON() ([]byte, error)        { return nil, errors.ErrUnsupported }
func (RenderedMessage) MarshalJSON() ([]byte, error) { return nil, errors.ErrUnsupported }

// MarshalText refuses implicit sensitive text serialization.
func (Template) MarshalText() ([]byte, error)        { return nil, errors.ErrUnsupported }
func (RenderedMessage) MarshalText() ([]byte, error) { return nil, errors.ErrUnsupported }
