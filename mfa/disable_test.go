package mfa_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func disableRequest(t *testing.T) mfa.DisableRequest {
	t.Helper()
	r := factorUpdateRequest(t)
	r.FactorProof.Purpose = "identity.mfa.disable"
	r.Caller.Request.Action = "identity.mfa.disable"
	return mfa.DisableRequest{TenantID: r.TenantID, CommandID: r.CommandID,
		Target: mfa.OneFactor, FactorID: r.FactorID,
		FactorProof: r.FactorProof, Session: r.Session,
		CSRFToken: r.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network,
		IdempotencyKey: r.IdempotencyKey}
}

func TestDisableRequiresExplicitTargetAndExactPurpose(t *testing.T) {
	r := disableRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid one-factor disable rejected", err)
	}
	all := r
	all.CommandID = ""
	all.Target, all.FactorID = mfa.AllFactors, ""
	if err := all.Validate(); err != nil {
		t.Fatal("explicit all-factor disable cannot use owner-derived command", err)
	}
	for _, change := range []func(*mfa.DisableRequest){
		func(r *mfa.DisableRequest) { r.Target = 0 },
		func(r *mfa.DisableRequest) { r.Target = 255 },
		func(r *mfa.DisableRequest) { r.FactorID = "" },
		func(r *mfa.DisableRequest) { r.Target = mfa.AllFactors },
		func(r *mfa.DisableRequest) { r.FactorID = "malformed" },
		func(r *mfa.DisableRequest) { r.FactorProof.Purpose = "identity.mfa.factor-update" },
		func(r *mfa.DisableRequest) { r.FactorProof.Purpose = "identity.mfa.recovery-regenerate" },
		func(r *mfa.DisableRequest) { r.FactorProof.Method = "recovery-code" },
		func(r *mfa.DisableRequest) { r.FactorProof.Assurance = auth.AssuranceSingleFactor },
		func(r *mfa.DisableRequest) { r.Caller.Request.Action = "identity.mfa.factor-update" },
		func(r *mfa.DisableRequest) { r.Caller.Request.Resource.ID = "foreign" },
		func(r *mfa.DisableRequest) { r.Session = auth.BearerCredential{} },
		func(r *mfa.DisableRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
	} {
		bad := r
		bad.Caller = r.Caller.Clone()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("ambiguous target or substituted disable authority admitted")
		}
	}
}

func TestDisableDoesNotImplicitlyExportCustody(t *testing.T) {
	r := disableRequest(t)
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, r); !strings.Contains(out, "redacted") || strings.Contains(out, string(r.FactorID)) {
			t.Fatal("disable diagnostics traverse borrowed custody")
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("disable request exported borrowed credentials")
	}
}
