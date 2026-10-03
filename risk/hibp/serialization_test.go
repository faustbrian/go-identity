package hibp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSensitiveValuesRefuseSerializationAndRenderOnlyRedaction(t *testing.T) {
	request := attributedRequest(t, "synthetic-serialization-candidate")
	derived, err := deriveCandidate(context.Background(), request.Candidate, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer derived.clear()
	data := rangeData{entries: []rangeEntry{{suffix: derived.suffix, count: 7}}}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{derived, &derived, data, &data, request, &request} {
		for _, marshal := range []func() ([]byte, error){value.MarshalJSON, value.MarshalText, func() ([]byte, error) { return json.Marshal(value) }} {
			encoded, err := marshal()
			if !errors.Is(err, errSensitive) || len(encoded) != 0 {
				t.Fatal("sensitive custody serialized or lost error identity")
			}
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(verb, value)
			if !strings.Contains(rendered, "redacted") {
				t.Fatal("sensitive value lacked explicit redaction")
			}
			for _, forbidden := range []string{"synthetic-serialization-candidate", string(derived.prefix[:]), string(derived.suffix[:]), request.SubjectScope, string(request.ReplayID), string(request.Attribution.AttemptID)} {
				if strings.Contains(rendered, forbidden) {
					t.Fatal("diagnostics exposed candidate or workflow custody")
				}
			}
		}
	}
}
