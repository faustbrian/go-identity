package postgres

import (
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestProtectedCountersPreserveOriginalSessionCustody(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := protectedCommand(t, "counter-tenant").Feature()
	spec.Operation.Owner, spec.Operation.OperationID, spec.Operation.SchemaID = "identity/mfa", "identity.mfa.enable", "mfa-enable"
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	token := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	original, err := identity.NewFeatureSessionCommand(spec, token)
	if err != nil {
		t.Fatal(err)
	}
	mapped, plan, err := r.PrepareCommandCounters(original, risk.Subject{User: "subject", Session: "source-session", Network: "192.0.2.1"}, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	got, has := mapped.SessionToken()
	if !has || got.Token() != token.Token() {
		t.Fatal("protected counter mapping discarded original session custody")
	}
	if err := r.ValidateCommandCounters(mapped, plan); err != nil {
		t.Fatal("preserved original custody broke native counter reconstruction")
	}
	if _, has := original.SessionToken(); !has {
		t.Fatal("mapping consumed borrowed session custody")
	}
}
