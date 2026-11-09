package oauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func TestCallbackRateAttributionCannotEscapeThroughDiagnostics(t *testing.T) {
	value := oauth.CallbackRateContext{ProviderID: "configured-provider", TransactionID: "private-transaction-correlation", Lifetime: time.Minute}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		text := fmt.Sprintf(format, value)
		if !strings.Contains(text, "redacted") || strings.Contains(text, value.ProviderID) || strings.Contains(text, value.TransactionID) {
			t.Fatal("private callback-rate attribution escaped formatting")
		}
	}
	if wire, err := json.Marshal(value); err == nil || len(wire) != 0 {
		t.Fatal("private callback-rate attribution serialized")
	}
	if wire, err := value.MarshalText(); err == nil || len(wire) != 0 {
		t.Fatal("private callback-rate attribution exported as text")
	}
}
