package session

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
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

func TestPreAuthIssueExecutionRedactsReceipt(t *testing.T) {
	execution := PreAuthIssueExecution{Receipt: identity.CommandResult{Binding: identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", CorrelationID: "original-correlation"}}, Replayed: true}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, execution)
		if strings.Contains(got, string(execution.Receipt.Binding.CommandID)) || strings.Contains(got, execution.Receipt.Binding.CorrelationID) {
			t.Fatal("execution receipt disclosed original custody")
		}
	}
	if _, err := json.Marshal(execution); err == nil {
		t.Fatal("execution receipt implicitly serialized")
	}
	if _, err := execution.MarshalText(); err == nil {
		t.Fatal("execution receipt exported as text")
	}
}
