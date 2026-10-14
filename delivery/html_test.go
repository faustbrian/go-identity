package delivery

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"
)

func htmlTemplate() Template {
	t := plainTemplate()
	t.ContentType = "text/html"
	t.Subject = "Verify"
	t.Body = `<p title="{{.name}}">Hello {{.name}} <a href="{{.link}}">Verify</a></p>`
	t.RequiredVariables = []string{"name", "link"}
	t.VariableSchema = []VariableSchema{{Name: "name", Kind: "text"}, {Name: "link", Kind: "url", Sensitive: true}}
	t.AllowedOrigins = []string{"https://example.invalid"}
	return t
}

func htmlMessage() Message {
	m := validMessage()
	m.Variables = []TemplateVariable{
		{Name: "name", Kind: "text", TextValue: `<img src=x onerror="attack"> & "quoted"`},
		{Name: "link", Kind: "url", URLValue: "https://example.invalid/verify?x=synthetic&y=2", Sensitive: true},
	}
	return m
}

func TestHTMLRendererEscapesTextAttributesAndBindsOrigins(t *testing.T) {
	r, err := NewTemplateRenderer([]Template{htmlTemplate()})
	if err != nil {
		t.Fatal("safe HTML declaration rejected")
	}
	out, err := r.Render(context.Background(), htmlMessage())
	if err != nil || out.ContentType != "text/html" {
		t.Fatal("HTML render failed")
	}
	if strings.Contains(out.Body, "<img") || !strings.Contains(out.Body, "&lt;img") || !strings.Contains(out.Body, `href="https://example.invalid/verify?x=synthetic&amp;y=2"`) {
		t.Fatal("unsafe final HTML context")
	}
	m := htmlMessage()
	m.Variables[1].URLValue = "https://evil.invalid/verify"
	if _, err := r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("origin bypass")
	}
}

func TestHTMLRendererRejectsActiveAmbiguousAndUndeclaredContexts(t *testing.T) {
	for i, body := range []string{
		`<script>{{.name}}</script>`, `<style>{{.name}}</style>`, `<svg><a href="{{.link}}">x</a></svg>`,
		`<p onclick="{{.name}}">x</p>`, `<p style="{{.name}}">x</p>`,
		`<a href="{{.name}}">x</a>`, `<a href="{{.link}}.evil.invalid">x</a>`,
		`<a href="https://evil.invalid/?x={{.link}}">x</a>`,
		`<a href="javascript:attack">x</a>`, `<a href="https://evil.invalid">x</a>`,
		`<a href="&#106;avascript:attack">x</a>`,
		`<img srcset="{{.link}} 1x">`, `<p {{.name}}="x">x</p>`, `<{{.name}}>x</{{.name}}>`,
		`<!--{{.name}}-->`,
	} {
		tpl := htmlTemplate()
		tpl.Body = body
		if _, err := NewTemplateRenderer([]Template{tpl}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("unsafe context admitted in case %d", i)
		}
	}
}

func TestHTMLRendererSerializesDuplicateAttributesWithHTML5Semantics(t *testing.T) {
	tpl := htmlTemplate()
	tpl.Body = `<a href="{{.link}}" href="javascript:attack">Verify</a>`
	r, err := NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Render(context.Background(), htmlMessage())
	if err != nil || strings.Count(out.Body, "href=") != 1 || strings.Contains(out.Body, "javascript") {
		t.Fatal("discarded duplicate survived canonicalization")
	}
}

func TestHTMLRendererBoundsEscapedOutputAndPreservesPlainBehavior(t *testing.T) {
	tpl := htmlTemplate()
	tpl.Subject = ""
	tpl.Body = `<p>{{.name}}</p>`
	tpl.MaxRenderedBytes = 12
	r, err := NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	m := htmlMessage()
	m.Variables[0].TextValue = "&"
	out, err := r.Render(context.Background(), m)
	if err != nil || out.Body != "<p>&amp;</p>" {
		t.Fatal("exact escaped output boundary failed")
	}
	tpl.MaxRenderedBytes = 11
	r, err = NewTemplateRenderer([]Template{tpl})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Render(context.Background(), m); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("escaped output exceeds limit")
	}
}

func FuzzHTMLTemplate(f *testing.F) {
	f.Add(`<p title="{{.name}}">{{.name}} <a href="{{.link}}">verify</a></p>`, `<script>synthetic</script>`)
	f.Add(`<a href="{{.link}}.evil.invalid">x</a>`, "synthetic")
	f.Fuzz(func(t *testing.T, source, value string) {
		if len(source) > 2048 || len(value) > 2048 {
			t.Skip()
		}
		tpl := htmlTemplate()
		tpl.Subject = ""
		tpl.Body = source
		tpl.MaxRenderedBytes = 4096
		r, err := NewTemplateRenderer([]Template{tpl})
		if err != nil {
			return
		}
		m := htmlMessage()
		m.Variables[0].TextValue = value
		out, err := r.Render(context.Background(), m)
		if err != nil {
			return
		}
		if out.Body == "" || len(out.Body) > 4096 || out.ContentType != "text/html" {
			t.Fatal("render bounds violated")
		}
		doc, err := nethtml.Parse(strings.NewReader(out.Body))
		if err != nil {
			t.Fatal("canonical output parse failed")
		}
		for n := range doc.Descendants() {
			if n.Type != nethtml.ElementNode {
				continue
			}
			if n.Data != "html" && n.Data != "head" && n.Data != "body" && !emailElement(n.Data) {
				t.Fatal("active element appeared")
			}
			for _, a := range n.Attr {
				if strings.HasPrefix(a.Key, "on") || a.Key == "style" || a.Key == "srcset" {
					t.Fatal("active attribute appeared")
				}
				if a.Key == "href" || a.Key == "src" {
					u, err := url.Parse(a.Val)
					if err != nil || u.Scheme != "https" || originKey(u) != "example.invalid:443" || u.User != nil {
						t.Fatal("link authority expanded")
					}
				}
			}
		}
	})
}
