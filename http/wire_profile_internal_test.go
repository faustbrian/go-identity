package identityhttp

import (
	"context"
	"strings"
	"testing"

	openapi "github.com/faustbrian/go-openapi/v2"
)

func TestWireProfileRecursiveSchemaTerminates(t *testing.T) {
	doc, err := openapi.ParseJSON(context.Background(), strings.NewReader(`{"openapi":"3.1.1","info":{"title":"Identity","version":"1"},"paths":{},"components":{"schemas":{"Recursive":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Recursive"}}}}}}`), wireLimits(65536))
	if err != nil {
		t.Fatal(err)
	}
	p := wireProfile{ctx: context.Background(), document: doc}
	if err := p.walk(doc.Raw(), "document"); err != nil {
		t.Fatalf("recursive profile traversal failed: %v (references=%d)", err, p.references)
	}
	if p.depth != 0 || len(p.active) != 0 || p.references > 3 {
		t.Fatal("recursive traversal leaked active state or expanded without bound")
	}
}
