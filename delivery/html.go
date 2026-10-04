package delivery

import (
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"

	nethtml "golang.org/x/net/html"
)

const markerPrefix = "GOLIBDELIVERYVAR"

// Trust only reserialized HTML5 tokens, never original markup. The closed
// vocabulary excludes raw-text, foreign and active contexts; substitutions
// therefore use HTML escaping in text and quoted attributes alike.
func compileHTML(source string, schema map[string]VariableSchema, origins map[string]bool) ([]segment, error) {
	if strings.Contains(html.UnescapeString(source), markerPrefix) {
		return nil, ErrInvalidInput
	}
	parts, err := compileSegments(source, schema)
	if err != nil {
		return nil, err
	}
	var marked strings.Builder
	markers := make(map[string]string)
	for i, part := range parts {
		if part.variable == "" {
			marked.WriteString(part.text)
		} else {
			marker := fmt.Sprintf("%s%dX", markerPrefix, i)
			markers[marker] = part.variable
			marked.WriteString(marker)
		}
	}
	z := nethtml.NewTokenizer(strings.NewReader(marked.String()))
	z.SetMaxBuf(2 * 262144)
	var out []segment
	seen := make(map[string]bool)
	for count := 0; ; count++ {
		if count > 65536 {
			return nil, ErrInvalidInput
		}
		kind := z.Next()
		if kind == nethtml.ErrorToken {
			if z.Err() != io.EOF || len(seen) != len(markers) {
				return nil, ErrInvalidInput
			}
			return out, nil
		}
		token := z.Token()
		switch kind {
		case nethtml.TextToken:
			segments, err := htmlSegments(token.Data, markers, make(map[string]bool))
			if err != nil || checkPlainURLs(segments, schema) != nil {
				return nil, ErrInvalidInput
			}
		case nethtml.StartTagToken, nethtml.EndTagToken, nethtml.SelfClosingTagToken:
			if !emailElement(token.Data) || len(token.Attr) > 32 {
				return nil, ErrInvalidInput
			}
			attrs := make(map[string]bool)
			for _, a := range token.Attr {
				if a.Namespace != "" || attrs[a.Key] || !boundedText(a.Val, 0, 4096) {
					return nil, ErrInvalidInput
				}
				attrs[a.Key] = true
				if err := checkAttribute(token.Data, a.Key, a.Val, markers, schema, origins); err != nil {
					return nil, err
				}
			}
		default:
			return nil, ErrInvalidInput
		}
		segments, err := htmlSegments(token.String(), markers, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, segments...)
	}
}

func emailElement(tag string) bool {
	switch tag {
	case "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col", "colgroup", "dd", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "s", "small", "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "u", "ul":
		return true
	}
	return false
}

func checkAttribute(tag, key, value string, markers map[string]string, schema map[string]VariableSchema, origins map[string]bool) error {
	switch key {
	case "href", "src":
		if (key == "href" && tag != "a") || (key == "src" && tag != "img") {
			return ErrInvalidInput
		}
		if variable, ok := markers[value]; ok {
			if schema[variable].Kind != "url" {
				return ErrInvalidInput
			}
			return nil
		}
		if strings.Contains(value, markerPrefix) || (TemplateVariable{Name: "link", Kind: "url", URLValue: value}).Validate() != nil {
			return ErrInvalidInput
		}
		u, _ := url.Parse(value)
		if !origins[originKey(u)] {
			return ErrInvalidInput
		}
	case "title", "alt", "aria-label":
		parts, err := htmlSegments(value, markers, make(map[string]bool))
		if err != nil {
			return err
		}
		for _, part := range parts {
			if part.variable != "" && schema[part.variable].Kind == "url" {
				return ErrInvalidInput
			}
		}
	case "class", "id", "lang", "dir", "align", "valign", "width", "height", "border", "cellpadding", "cellspacing", "colspan", "rowspan", "bgcolor":
		if strings.Contains(value, markerPrefix) {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func htmlSegments(text string, markers map[string]string, seen map[string]bool) ([]segment, error) {
	var out []segment
	for {
		i := strings.Index(text, markerPrefix)
		if i < 0 {
			if text != "" {
				out = append(out, segment{text: text})
			}
			return out, nil
		}
		if i > 0 {
			out = append(out, segment{text: text[:i]})
		}
		text = text[i:]
		end := strings.IndexByte(text, 'X')
		if end < 0 {
			return nil, ErrInvalidInput
		}
		marker := text[:end+1]
		variable, ok := markers[marker]
		if !ok {
			return nil, ErrInvalidInput
		}
		seen[marker] = true
		out = append(out, segment{variable: variable, escape: true})
		text = text[end+1:]
	}
}
