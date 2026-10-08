package identityhttp

import (
	"context"
	"strings"

	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/jsonschema"
	"github.com/faustbrian/go-openapi/v2/jsonvalue"
	"github.com/faustbrian/go-openapi/v2/reference"
)

// wireProfile selects structural locations, not arbitrary member spellings.
// The OpenAPI owner still owns schema compilation, pointer resolution and
// normative validation. This layer imposes only our self-contained profile.
// In particular a properties map names application fields, including "$ref";
// examples, defaults, constants and extension payloads are ordinary data.
type wireProfile struct {
	ctx        context.Context
	document   openapi.Document
	references int
	depth      int
	active     map[string]bool
	compiler   *jsonschema.Compiler
}

func (p *wireProfile) walk(value jsonvalue.Value, role string) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 64 {
		return ErrInvalidInput
	}
	if role == "schemaRoot" {
		if err := p.compile(value); err != nil {
			return err
		}
		role = "schema"
	}
	if elements, ok := value.Elements(); ok {
		child := ""
		if role == "parameters" {
			child = "parameter"
		} else if role == "schemaArray" {
			child = "schema"
		}
		if child != "" {
			for _, element := range elements {
				if err := p.walk(element, child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	members, _ := value.Members()
	for _, member := range members {
		// These patterned structural collections permit specification extensions.
		// Named component/property maps do not: x-* there is a real user name.
		if (role == "pathItems" || role == "responses" || role == "callback") && strings.HasPrefix(member.Name, "x-") {
			continue
		}
		// Collection member names are never keywords.
		child, collection := wireCollectionChild(role)
		// A Callback Object may instead be a Reference Object; $ref is not a
		// runtime-expression entry and must retain the closed-reference guard.
		if role == "callback" && member.Name == "$ref" {
			collection = false
		}
		if !collection {
			if role == "link" && member.Name == "operationRef" {
				raw, ok := member.Value.Text()
				if !ok || !strings.HasPrefix(raw, "#/") {
					return ErrInvalidInput
				}
				fragment, err := reference.ParseFragment(raw[1:])
				if err != nil {
					return ErrInvalidInput
				}
				if _, err := fragment.Pointer().Evaluate(p.document.Raw()); err != nil {
					return ErrInvalidInput
				}
			}
			if member.Name == "$ref" {
				p.references++
				raw, ok := member.Value.Text()
				if !ok || !strings.HasPrefix(raw, "#/") || p.references > 8192 {
					return ErrInvalidInput
				}
				fragment, err := reference.ParseFragment(raw[1:])
				if err != nil {
					return ErrInvalidInput
				}
				target, err := fragment.Pointer().Evaluate(p.document.Raw())
				if err != nil {
					return ErrInvalidInput
				}
				if target.Kind() != jsonvalue.ObjectKind && (role != "schema" || target.Kind() != jsonvalue.BooleanKind) {
					return ErrInvalidInput
				}
				// A referenced extension value is no longer opaque data. Validate
				// it as the source object, including nested schemas and aliases.
				// Schema recursion is legal; Reference Object cycles are not.
				key := role + "\x00" + fragment.Pointer().String()
				if p.active[key] {
					if role != "schema" {
						return ErrInvalidInput
					}
				} else {
					if p.active == nil {
						p.active = make(map[string]bool)
					}
					p.active[key] = true
					err := p.walk(target, role)
					delete(p.active, key)
					if err != nil {
						return err
					}
				}
			}
			if role == "schema" && (member.Name == "$id" || member.Name == "$dynamicRef") || role == "example" && member.Name == "externalValue" {
				return ErrInvalidInput
			}
			child = wireMemberChild(role, member.Name)
		}
		if child != "" {
			if err := p.walk(member.Value, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *wireProfile) compile(schema jsonvalue.Value) error {
	if p.compiler == nil {
		compiler, err := jsonschema.NewCompilerForDocument(p.document, jsonschema.WithTraversalLimits(200000, 64))
		if err != nil {
			return err
		}
		p.compiler = compiler
	}
	// A detached Schema Object is not the resolution root of document-relative
	// pointers. Retain the immutable document as the root and compile the selected
	// schema through allOf, so components and recursive pointers keep their exact
	// meaning. OpenAPI root members are annotations to the JSON Schema evaluator.
	members, _ := p.document.Raw().Members()
	all, err := jsonvalue.Array([]jsonvalue.Value{schema})
	if err != nil {
		return err
	}
	members = append(members, jsonvalue.Member{Name: "allOf", Value: all})
	root, err := jsonvalue.Object(members)
	if err != nil {
		return err
	}
	_, err = p.compiler.Compile(p.ctx, root)
	return err
}

func wireCollectionChild(role string) (string, bool) {
	switch role {
	case "pathItems", "callback":
		return "pathItem", true
	case "responses":
		return "response", true
	case "content":
		return "mediaType", true
	case "headers", "parameterMap":
		return "parameter", true
	case "callbacks":
		return "callback", true
	case "requestBodies":
		return "requestBody", true
	case "encoding":
		return "encodingEntry", true
	case "schemaRoots":
		return "schemaRoot", true
	case "schemaMap":
		return "schema", true
	case "securitySchemes":
		return "securityScheme", true
	case "examples":
		return "example", true
	case "links":
		return "link", true
	}
	return "", false
}

func wireMemberChild(role, name string) string {
	switch role {
	case "document":
		if name == "paths" || name == "webhooks" {
			return "pathItems"
		}
		if name == "components" {
			return "components"
		}
	case "components":
		switch name {
		case "schemas":
			return "schemaRoots"
		case "parameters":
			return "parameterMap"
		case "pathItems", "responses", "headers", "requestBodies", "callbacks", "securitySchemes", "examples", "links":
			return name
		}
	case "pathItem":
		switch name {
		case "get", "put", "post", "delete", "options", "head", "patch", "trace":
			return "operation"
		case "parameters":
			return "parameters"
		}
	case "operation":
		switch name {
		case "parameters", "requestBody", "responses", "callbacks":
			return name
		}
	case "response":
		switch name {
		case "content", "headers", "links":
			return name
		}
	case "requestBody":
		if name == "content" {
			return "content"
		}
	case "mediaType", "parameter":
		switch name {
		case "schema":
			return "schemaRoot"
		case "content", "examples":
			return name
		case "encoding":
			if role == "mediaType" {
				return "encoding"
			}
		}
	case "encodingEntry":
		if name == "headers" {
			return "headers"
		}
	case "schema":
		switch name {
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
			return "schemaMap"
		case "allOf", "anyOf", "oneOf", "prefixItems":
			return "schemaArray"
		case "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "propertyNames", "items", "contains", "not", "if", "then", "else", "contentSchema":
			return "schema"
		}
	}
	return ""
}
