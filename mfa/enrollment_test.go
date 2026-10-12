package mfa

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
	primitive "github.com/faustbrian/go-password"
)

func enrollmentRequestFixture() EnableRequest {
	now := time.Date(2026, 10, 12, 6, 0, 0, 123456789, time.UTC)
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAw", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "backend", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, SessionID: "source-session", SessionVersion: 1, Action: "identity.mfa.enable"}
	key, _ := identity.NewIdempotencyKey([]byte("fixture-enrollment-key"))
	primary := proof.Proof
	primary.ID, primary.Purpose = "AAAAAAAAAAAAAAAAAAAABA", "identity.password.signin"
	return EnableRequest{TenantID: "tenant-a", FactorPolicy: FactorPolicy{Method: "totp", RecoveryCodes: 10}, PrimaryProof: primary, Reauthentication: proof, Session: auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-a", Action: "identity.mfa.enable", Subject: authorization.Subject{ID: "user-a", Kind: authorization.SubjectUser}, Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}}, Network: "192.0.2.1"}
}

func TestEnableRequestRequiresExactPrimaryReauthenticationAndCallerScope(t *testing.T) {
	r := enrollmentRequestFixture()
	if err := r.Validate(); err != nil {
		t.Fatal("valid bounded enrollment input denied")
	}
	for _, change := range []func(*EnableRequest){func(r *EnableRequest) { r.TenantID = "other" }, func(r *EnableRequest) { r.PrimaryProof.Subject = "other" }, func(r *EnableRequest) { r.Reauthentication.Action = "identity.password.change" }, func(r *EnableRequest) { r.Reauthentication.SessionVersion = 0 }, func(r *EnableRequest) { r.Session = auth.BearerCredential{} }, func(r *EnableRequest) { r.IdempotencyKey = identity.IdempotencyKey{} }, func(r *EnableRequest) { r.Caller.Request.Subject.ID = "other" }, func(r *EnableRequest) { r.Caller.PolicyRevision = 0 }, func(r *EnableRequest) { r.Network = "not-an-ip" }, func(r *EnableRequest) { r.FactorPolicy.Method = "" }, func(r *EnableRequest) { r.FactorPolicy.RecoveryCodes = 65 }, func(r *EnableRequest) { r.FactorPolicy.RecoveryCodes = 0 }} {
		bad := r
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("malformed or foreign enrollment scope accepted")
		}
	}
}

func TestEnableRequestAndResultNeverImplicitlyDiscloseCustody(t *testing.T) {
	r := enrollmentRequestFixture()
	code, err := primitive.NewSecret([]byte("sensitive-recovery-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	defer code.Destroy()
	material := RevealOnceCodes{Codes: []primitive.Secret{code}}
	for _, value := range []any{r, EnableResult{RecoveryMaterial: material}, material} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, "fixture-enrollment-key") || strings.Contains(text, "source-session") || strings.Contains(text, "sensitive-recovery-fixture") {
				t.Fatal("enrollment diagnostics traversed custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit enrollment export accepted")
		}
	}
}

func TestFactorPolicyRequiresExplicitPositiveRecoveryCount(t *testing.T) {
	for _, count := range []uint32{1, 10, 20, 64} {
		if err := (FactorPolicy{Method: "totp", RecoveryCodes: count}).Validate(); err != nil {
			t.Fatalf("bounded count %d denied", count)
		}
	}
	for _, policy := range []FactorPolicy{{}, {Method: "totp"}, {Method: "totp", RecoveryCodes: 65}, {Method: strings.Repeat("m", 257), RecoveryCodes: 10}, {Method: "totp\n", RecoveryCodes: 10}} {
		if policy.Validate() == nil {
			t.Fatal("invalid intrinsic policy accepted")
		}
	}
}

func TestEnableRequestValidationCannotAuthenticateOrRenewProofs(t *testing.T) {
	r := enrollmentRequestFixture()
	// Structural validation uses neither current time nor a signature source.
	// The original primary and protected-action proof are distinct projections.
	if r.PrimaryProof.ID == r.Reauthentication.Proof.ID || r.Validate() != nil {
		t.Fatal("distinct historical original proofs structurally denied")
	}
	for _, change := range []func(*EnableRequest){
		func(r *EnableRequest) { r.PrimaryProof = auth.Proof{} },
		func(r *EnableRequest) { r.Reauthentication.Proof = auth.Proof{} },
		func(r *EnableRequest) { r.PrimaryProof.ExpiresAt = r.PrimaryProof.IssuedAt },
		func(r *EnableRequest) { r.Reauthentication.SessionID = "" },
		func(r *EnableRequest) { r.Caller.Request.Resource.ID = "other" },
		func(r *EnableRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		func(r *EnableRequest) { r.Session = auth.NewBearerCredential(strings.Repeat("A", 4096)) },
	} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("incomplete or foreign structural scope accepted")
		}
	}
}

func TestRevealOnceRecoveryMaterialSupportsExplicitTransferAndDestruction(t *testing.T) {
	code, err := primitive.NewSecret([]byte("synthetic-recovery-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer code.Destroy()
	material := RevealOnceCodes{Codes: []primitive.Secret{code}}
	delivered := false
	if err := material.Codes[0].Use(func(raw []byte) error {
		delivered = string(raw) == "synthetic-recovery-output"
		return nil
	}); err != nil || !delivered {
		t.Fatal("opaque recovery output cannot be explicitly delivered")
	}
	material.Codes[0].Destroy()
	if code.Len() != 0 || material.Codes[0].Use(func([]byte) error { return nil }) == nil {
		t.Fatal("destroyed recovery material remained usable")
	}
}
