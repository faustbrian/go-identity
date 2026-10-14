package mfa_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	primitive "github.com/faustbrian/go-password"
)

func regenerationRequest() mfa.RecoveryRegenerateRequest {
	at := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	return mfa.RecoveryRegenerateRequest{
		TenantID: "tenant-a", CommandID: "AAAAAAAAAAAAAAAAAAAAAQ",
		FactorProof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAg", Tenant: "tenant-a", Subject: "user-a", Method: "totp", Assurance: auth.AssuranceMultiFactor, Purpose: "identity.mfa.recovery-regenerate", Audience: "backend", IssuedAt: at, ExpiresAt: at.Add(time.Minute)},
		Session:     auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))),
		Caller:      authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-a", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"}, Action: "identity.mfa.recovery-regenerate", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}},
		Origin:      "https://app.example", Network: "192.0.2.1",
	}
}

func TestRegenerationRequiresPurposeBoundFactorAndExactCurrentCaller(t *testing.T) {
	r := regenerationRequest()
	// Structural admission must not consult a clock: native original recovery
	// may need an expired, structurally intact request. This is not authority.
	if err := r.Validate(); err != nil {
		t.Fatal("well-formed original request rejected", err)
	}
	for _, change := range []func(*mfa.RecoveryRegenerateRequest){
		func(r *mfa.RecoveryRegenerateRequest) { r.CommandID = identity.CommandID(r.FactorProof.ID) },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof = auth.Proof{} },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Purpose = "identity.mfa.complete" },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Method = "recovery-code" },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Method = "password" },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Assurance = auth.AssuranceSingleFactor },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Subject = "other-user" },
		func(r *mfa.RecoveryRegenerateRequest) { r.FactorProof.Tenant = "other-tenant" },
		func(r *mfa.RecoveryRegenerateRequest) { r.Session = auth.BearerCredential{} },
		func(r *mfa.RecoveryRegenerateRequest) {
			r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
		func(r *mfa.RecoveryRegenerateRequest) { r.Caller.Request.Resource.ID = "other-user" },
		func(r *mfa.RecoveryRegenerateRequest) { r.Caller.Request.Action = "identity.mfa.enable" },
		func(r *mfa.RecoveryRegenerateRequest) { r.Caller.PolicyRevision = 0 },
		func(r *mfa.RecoveryRegenerateRequest) { r.Origin = "https://app.example/path" },
		func(r *mfa.RecoveryRegenerateRequest) { r.Origin = "https://app.example#" },
		func(r *mfa.RecoveryRegenerateRequest) { r.Network = "not-an-ip" },
	} {
		bad := r
		bad.Caller = r.Caller.Clone()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("foreign or ineligible regeneration input admitted")
		}
	}
}

func TestRegenerationNeverImplicitlyExportsRequestOrRevealMaterial(t *testing.T) {
	secret, err := primitive.NewSecret([]byte("synthetic-replacement-recovery-code"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	result := mfa.RecoveryRegenerateResult{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", Outcome: identity.CommitOutcomeCommitted, RecoveryCodes: mfa.RevealOnceCodes{Codes: []primitive.Secret{secret}}}
	for _, value := range []any{regenerationRequest(), result} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, "synthetic-replacement-recovery-code") || strings.Contains(text, "user-a") {
				t.Fatal("regeneration diagnostics traversed custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit regeneration export accepted")
		}
	}
}
