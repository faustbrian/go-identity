package identityhttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestComposedDocumentValidatesAllSchemasWithinConstructionBudget(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		var ops []identityhttp.OperationDescriptor
		for i := 0; i < 12; i++ {
			op := extensionDescriptor(t, "composed", fmt.Sprintf("read%d", i))
			responses := map[string]any{}
			for j := 0; j < 8; j++ {
				properties := map[string]any{}
				for k := 0; k < 16; k++ {
					properties[fmt.Sprintf("field%d", k)] = map[string]any{"type": "string", "maxLength": 128, "pattern": "^[!-~]{1,128}$"}
				}
				if invalid && i == 11 && j == 7 {
					properties["lateInvalid"] = map[string]any{"type": "string", "maxLength": -1}
				}
				result := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
				responses[fmt.Sprintf("%d", 200+j)] = map[string]any{"description": "Bounded composed result", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"oneOf": []any{result, map[string]any{"type": "object", "properties": map[string]any{"error": map[string]any{"type": "string", "enum": []string{"denied", "unavailable", "invalid"}}}, "required": []string{"error"}, "additionalProperties": false}}}}}}
			}
			definition, err := json.Marshal(map[string]any{"operationId": op.Record.OperationID, "responses": responses})
			if err != nil {
				t.Fatal(err)
			}
			op.Wire = &identityhttp.WireOperation{Definition: definition}
			ops = append(ops, op)
		}
		f := feature(t, "composed", nil, ops...)
		h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Composed", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
		if invalid {
			if err == nil || h != nil || len(doc.JSON()) != 0 {
				t.Fatal("late invalid schema escaped whole-document validation")
			}
		} else if err != nil || h == nil || len(doc.Operations()) != 12 {
			t.Fatal("valid multi-operation composition exhausted construction budget", err)
		}
	}
}
