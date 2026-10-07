package session

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPreAuthIssueCommandRedactsOriginalCustody(t *testing.T) {
	_, _, spec := preAuthFixture(t)
	record, err := NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	c := PreAuthIssueCommand{CommandID: "AgICAgICAgICAgICAgICAg", CorrelationID: "original-correlation", Record: record}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, c)
		if strings.Contains(got, string(c.CommandID)) || strings.Contains(got, c.CorrelationID) || strings.Contains(got, spec.Binding.Intent.Origin) {
			t.Fatal("original command custody disclosed")
		}
	}
	if _, err = json.Marshal(c); err == nil {
		t.Fatal("original command implicitly serialized")
	}
	if _, err = c.MarshalText(); err == nil {
		t.Fatal("original command exported as text")
	}
}
