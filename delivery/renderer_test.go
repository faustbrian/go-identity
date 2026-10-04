package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func plainTemplate() Template {
	return Template{ID: "verify", Version: 1, Channel: ChannelEmail, Locale: "en",
		Subject: "Verify {{.name}}", Body: "Hello {{.name}}", ContentType: "text/plain",
		RequiredVariables: []string{"name"}, VariableSchema: []VariableSchema{{Name: "name", Kind: "text"}}, MaxRenderedBytes: 4096}
}

func TestRendererSelectsExactVersionAndOrderedLocale(t *testing.T) {
	a, b := plainTemplate(), plainTemplate()
	b.Locale, b.Body = "en-US", "US {{.name}}"
	r, err := NewTemplateRenderer([]Template{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// Caller mutation must not affect the compiled immutable catalog.
	b.Body = "changed"
	m := validMessage()
	out, err := r.Render(context.Background(), m)
	if err != nil || out.Locale != "en-US" || out.Body != "US synthetic-display" || out.ContentType != "text/plain" {
		t.Fatal("ordered render failed")
	}
	m.LocaleChain = []string{"fr", "en"}
	out, err = r.Render(context.Background(), m)
	if err != nil || out.Locale != "en" || out.Subject != "Verify synthetic-display" {
		t.Fatal("fallback failed")
	}
	m.TemplateVersion = 2
	if _, err = r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("version silently substituted")
	}
}

func TestRendererSchemaOriginBoundsAndHeaderSafety(t *testing.T) {
	r, err := NewTemplateRenderer([]Template{plainTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Message){
		func(m *Message) { m.Variables = nil },
		func(m *Message) { m.Variables = append(m.Variables, TemplateVariable{Name: "extra", Kind: "text"}) },
		func(m *Message) {
			m.Variables[0] = TemplateVariable{Name: "name", Kind: "code", CodeValue: "synthetic"}
		},
		func(m *Message) { m.Variables[0].Sensitive = true },
		func(m *Message) { m.Variables[0].TextValue = "synthetic\r\nheader" },
	} {
		m := validMessage()
		mutate(&m)
		if _, err := r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unsafe schema or header admitted")
		}
	}
	tpl := plainTemplate()
	tpl.Subject = ""
	tpl.Body = "{{.name}}"
	tpl.MaxRenderedBytes = 3
	r, err = NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	m := validMessage()
	m.Variables[0].TextValue = "<&>"
	out, err := r.Render(context.Background(), m)
	if err != nil || out.Body != "<&>" {
		t.Fatal("plain text escaped or exact limit rejected")
	}
	m.Variables[0].TextValue = "four"
	if _, err := r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("output limit ignored")
	}
	tpl = plainTemplate()
	tpl.Subject = ""
	tpl.Body = "{{.name}}"
	tpl.VariableSchema[0].Kind = "url"
	tpl.AllowedOrigins = []string{"https://example.invalid"}
	r, err = NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	m.Variables[0] = TemplateVariable{Name: "name", Kind: "url", URLValue: "https://example.invalid/verify?synthetic"}
	if _, err := r.Render(context.Background(), m); err != nil {
		t.Fatal("allowed URL rejected")
	}
	for _, origin := range []string{"https://evil.invalid", "https://example.invalid:444", "https://example.invalid.evil.invalid"} {
		m.Variables[0].URLValue = origin
		if _, err := r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("origin bypass")
		}
	}
}

func TestRendererRejectsExecutableTemplatesAndRedacts(t *testing.T) {
	for _, body := range []string{"{{range .name}}x{{end}}", "{{printf \"%s\" .name}}", "{{.name.field}}", "{{.missing}}", "{{.name", "{{template \"x\"}}"} {
		tpl := plainTemplate()
		tpl.Body = body
		if _, err := NewTemplateRenderer([]Template{tpl}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unsupported executable template accepted")
		}
	}
	r, err := NewTemplateRenderer([]Template{plainTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Render(ctx, validMessage()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	out, err := r.Render(context.Background(), validMessage())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", out), "synthetic") {
		t.Fatal("rendered diagnostics leaked")
	}
}

func TestRendererCatalogAndZeroBounds(t *testing.T) {
	for _, mutate := range []func(*Template){
		func(t *Template) { t.ID = "" }, func(t *Template) { t.Version = 0 },
		func(t *Template) { t.Channel = 0 }, func(t *Template) { t.Locale = "" },
		func(t *Template) { t.ContentType = "text/html" }, func(t *Template) { t.Body = "" },
		func(t *Template) { t.MaxRenderedBytes = 0 }, func(t *Template) { t.MaxRenderedBytes = 262145 },
		func(t *Template) { t.Subject = strings.Repeat("s", 999) },
		func(t *Template) { t.RequiredVariables = []string{"name", "name"} },
		func(t *Template) { t.VariableSchema[0].Name = "other" },
		func(t *Template) { t.VariableSchema[0].Kind = "unknown" },
		func(t *Template) { t.VariableSchema[0].Kind = "url" },
		func(t *Template) { t.AllowedOrigins = []string{"https://example.invalid/path"} },
		func(t *Template) {
			t.AllowedOrigins = []string{"https://example.invalid", "https://example.invalid:443"}
		},
		func(t *Template) { t.Channel = ChannelSMS },
	} {
		tpl := plainTemplate()
		mutate(&tpl)
		if _, err := NewTemplateRenderer([]Template{tpl}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid catalog admitted")
		}
	}
	if _, err := NewTemplateRenderer(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("empty catalog admitted")
	}
	if _, err := NewTemplateRenderer([]Template{plainTemplate(), plainTemplate()}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("duplicate template admitted")
	}
	tpl := plainTemplate()
	r, err := NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	tpl.RequiredVariables[0] = "changed"
	tpl.VariableSchema[0].Kind = "code"
	if _, err := r.Render(context.Background(), validMessage()); err != nil {
		t.Fatal("caller schema mutation affected catalog")
	}
	if _, err := r.Render(nil, validMessage()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context admitted")
	}
	var zero TemplateRenderer
	if _, err := zero.Render(context.Background(), validMessage()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero renderer admitted")
	}
}

func TestRendererRejectsURLConcatenationAndRedactsCatalogCopies(t *testing.T) {
	for _, body := range []string{"{{.name}}.evil.invalid", "https://evil.invalid/?{{.name}}", "{{.name}}{{.other}}"} {
		tpl := plainTemplate()
		tpl.Subject = ""
		tpl.Body = body
		tpl.VariableSchema[0].Kind = "url"
		tpl.AllowedOrigins = []string{"https://example.invalid"}
		if strings.Contains(body, ".other") {
			tpl.RequiredVariables = append(tpl.RequiredVariables, "other")
			tpl.VariableSchema = append(tpl.VariableSchema, VariableSchema{Name: "other", Kind: "text"})
		}
		if _, err := NewTemplateRenderer([]Template{tpl}); !errors.Is(err, ErrInvalidInput) {
			t.Error("URL origin can change through concatenation")
		}
	}
	tpl := plainTemplate()
	tpl.Body = "private-template-source {{.name}}"
	r, err := NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{r, *r} {
		if strings.Contains(fmt.Sprintf("%+v", v), "private-template-source") {
			t.Fatal("catalog value copy leaks diagnostics")
		}
	}
}

func FuzzPlainTemplate(f *testing.F) {
	f.Add("Hello {{.name}}", "synthetic")
	f.Add("{{range .name}}x{{end}}", "synthetic")
	f.Fuzz(func(t *testing.T, source, value string) {
		if len(source) > 2048 || len(value) > 2048 {
			t.Skip()
		}
		tpl := plainTemplate()
		tpl.Subject = ""
		tpl.Body = source
		tpl.MaxRenderedBytes = 1024
		r, err := NewTemplateRenderer([]Template{tpl})
		if err != nil {
			return
		}
		m := validMessage()
		m.Variables[0].TextValue = value
		out, err := r.Render(context.Background(), m)
		if err == nil && (out.Body == "" || len(out.Body) > 1024 || out.ContentType != "text/plain" || out.Locale != "en") {
			t.Fatal("render invariant violated")
		}
	})
}
