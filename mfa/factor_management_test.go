package mfa_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func factorUpdateRequest(t *testing.T) mfa.FactorUpdateRequest {
	t.Helper()
	r := regenerationRequest()
	r.FactorProof.Purpose = "identity.mfa.factor-update"
	r.Caller.Request.Action = "identity.mfa.factor-update"
	key, err := identity.NewIdempotencyKey([]byte("factor-management-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return mfa.FactorUpdateRequest{TenantID: r.TenantID, CommandID: r.CommandID, FactorID: "AAAAAAAAAAAAAAAAAAAABA", Action: mfa.Rename, Name: "work phone", ExpectedVersion: 3, FactorProof: r.FactorProof, Session: r.Session, Caller: r.Caller, Origin: r.Origin, Network: r.Network, IdempotencyKey: key}
}

func TestFactorUpdateRequiresExactTargetVersionActionAndProofCustody(t *testing.T) {
	r := factorUpdateRequest(t)
	for _, action := range []mfa.FactorUpdateAction{mfa.Rename, mfa.Remove, mfa.Replace} {
		valid := r
		valid.Action = action
		if action != mfa.Rename {
			valid.Name = ""
		}
		if err := valid.Validate(); err != nil {
			t.Fatal("well-formed factor mutation rejected", err)
		}
	}
	for _, change := range []func(*mfa.FactorUpdateRequest){
		func(r *mfa.FactorUpdateRequest) { r.TenantID = "" },
		func(r *mfa.FactorUpdateRequest) { r.CommandID = "malformed" },
		func(r *mfa.FactorUpdateRequest) { r.CommandID = identity.CommandID(r.FactorProof.ID) },
		func(r *mfa.FactorUpdateRequest) { r.FactorID = "" },
		func(r *mfa.FactorUpdateRequest) { r.Action = 0 },
		func(r *mfa.FactorUpdateRequest) { r.Action = 255 },
		func(r *mfa.FactorUpdateRequest) { r.Action = mfa.Remove },
		func(r *mfa.FactorUpdateRequest) { r.Action = mfa.Replace },
		func(r *mfa.FactorUpdateRequest) { r.Name = strings.Repeat("x", 129) },
		func(r *mfa.FactorUpdateRequest) { r.Name = "unsafe\nlabel" },
		func(r *mfa.FactorUpdateRequest) { r.Name = string([]byte{0xff}) },
		func(r *mfa.FactorUpdateRequest) { r.ExpectedVersion = 0 },
		func(r *mfa.FactorUpdateRequest) { r.ExpectedVersion = math.MaxUint64 },
		func(r *mfa.FactorUpdateRequest) { r.FactorProof.Purpose = "identity.mfa.disable" },
		func(r *mfa.FactorUpdateRequest) { r.FactorProof.Method = "recovery-code" },
		func(r *mfa.FactorUpdateRequest) { r.FactorProof.Assurance = auth.AssuranceSingleFactor },
		func(r *mfa.FactorUpdateRequest) { r.FactorProof.Subject = "foreign" },
		func(r *mfa.FactorUpdateRequest) { r.Session = auth.BearerCredential{} },
		func(r *mfa.FactorUpdateRequest) { r.Caller.Request.Action = "identity.mfa.disable" },
		func(r *mfa.FactorUpdateRequest) { r.Caller.Request.Resource.ID = "foreign" },
		func(r *mfa.FactorUpdateRequest) { r.Caller.PolicyRevision = 0 },
		func(r *mfa.FactorUpdateRequest) { r.Origin += "/path" },
		func(r *mfa.FactorUpdateRequest) { r.Network = "not-an-IP" },
		func(r *mfa.FactorUpdateRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
	} {
		bad := r
		bad.Caller = r.Caller.Clone()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("malformed or mismatched factor mutation admitted")
		}
	}
	r.Name = ""
	if r.Validate() != nil {
		t.Fatal("rename cannot clear an optional label")
	}
}

func TestFactorUpdateAllowsOwnerDerivedInitialCommand(t *testing.T) {
	r := factorUpdateRequest(t)
	r.CommandID = ""
	if err := r.Validate(); err != nil {
		t.Fatal("fresh keyed request cannot let its owner derive the command", err)
	}
}

func TestFactorUpdateRequestDoesNotImplicitlyExportCustody(t *testing.T) {
	r := factorUpdateRequest(t)
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(verb, r)
		if !strings.Contains(out, "redacted") || strings.Contains(out, "user-a") || strings.Contains(out, "work phone") {
			t.Fatal("factor management diagnostic traversed borrowed custody")
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("factor update exported borrowed credential")
	}
}

func TestAuthenticatedTOTPFactorManagementPurposesRemainExact(t *testing.T) {
	for _, purpose := range []auth.Purpose{"identity.mfa.factor-update", "identity.mfa.disable"} {
		r := authenticatedTOTPRequest(t)
		r.StepUp.Purpose = purpose
		if err := r.Validate(); err != nil {
			t.Fatalf("fresh authenticated factor-management step-up rejected for %s: %v", purpose, err)
		}
	}
	for _, purpose := range []auth.Purpose{"", "identity.mfa.enable", "identity.admin.mfa-reset", "identity.mfa.list", "identity.mfa.factor-update.extra"} {
		r := authenticatedTOTPRequest(t)
		r.StepUp.Purpose = purpose
		if r.Validate() == nil {
			t.Fatalf("unrelated action received factor-management proof admission: %s", purpose)
		}
	}
}

func TestFactorManagementProofProjectionCannotChangeItsProtectedAction(t *testing.T) {
	for _, purpose := range []auth.Purpose{"identity.mfa.factor-update", "identity.mfa.disable"} {
		r := regenerationRequest()
		r.FactorProof.Purpose = purpose
		original := auth.ReauthenticationProof{Proof: r.FactorProof, SessionID: "source-session", SessionVersion: 7, Action: string(purpose)}
		proof, err := mfa.NewContinuationProof(original)
		if err != nil || proof.Bindings() != original {
			t.Fatal("protected action or original session changed in proof projection")
		}
		forged := proof.Bindings()
		forged.Action = "identity.mfa.recovery-regenerate"
		if _, err := mfa.NewContinuationProof(forged); err == nil {
			t.Fatal("different action accepted without matching original purpose")
		}
		if proof.Bindings() != original {
			t.Fatal("caller changed retained proof through returned projection")
		}
	}
}
