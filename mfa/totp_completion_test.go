package mfa_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func totpRequestFixture(t *testing.T) mfa.TotpVerifyRequest {
	t.Helper()
	s := continuationFixture(t)
	continuation, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := continuation.CapabilityPayload("https://issuer.test")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("key-v1", []byte("0123456789abcdef0123456789abcdef"))
	wire, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	return mfa.TotpVerifyRequest{TenantID: s.TenantID, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", ChallengeID: mfa.ChallengeID(s.ID), FactorID: "AgICAgICAgICAgICAgICAg", Proof: proof, Code: code, PreAuthID: s.SourcePreAuthID, Cookie: auth.NewBearerCredential(strings.Repeat("A", 43)), Origin: s.Origin, Callback: "https://app.test/login", Network: "127.0.0.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(s.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "transport"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(s.ID)}}}}
}

func TestTOTPCompletionInputBoundsAndRedaction(t *testing.T) {
	request := totpRequestFixture(t)
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*mfa.TotpVerifyRequest){
		func(r *mfa.TotpVerifyRequest) { r.TenantID = "" }, func(r *mfa.TotpVerifyRequest) { r.CommandID = "" }, func(r *mfa.TotpVerifyRequest) { r.ChallengeID = "" }, func(r *mfa.TotpVerifyRequest) { r.FactorID = "foreign factor" }, func(r *mfa.TotpVerifyRequest) { r.Proof = capability.Proof{} }, func(r *mfa.TotpVerifyRequest) { r.Code = auth.OneTimeCode{} }, func(r *mfa.TotpVerifyRequest) { r.PreAuthID = "" }, func(r *mfa.TotpVerifyRequest) { r.Cookie = auth.BearerCredential{} }, func(r *mfa.TotpVerifyRequest) { r.Origin = "https://app.test/path" }, func(r *mfa.TotpVerifyRequest) { r.Callback = "https://user:password@app.test/login" }, func(r *mfa.TotpVerifyRequest) { r.Network = "not-an-ip" }, func(r *mfa.TotpVerifyRequest) { r.Device = strings.Repeat("x", 256) }, func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Tenant = "foreign" }, func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Action = "identity.mfa.enable" }, func(r *mfa.TotpVerifyRequest) { r.Caller.PolicyRevision = 0 }, func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Resource.ID = "foreign" },
	} {
		changed := request
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("unbounded/foreign TOTP completion input accepted")
		}
	}
	trusted := request
	trusted.TrustDevice = true
	if trusted.Validate() != nil {
		t.Fatal("policy request incorrectly treated as malformed input")
	}
	if fmt.Sprintf("%#v", request) != "mfa.TotpVerifyRequest(redacted)" {
		t.Fatal("factor/browser input disclosed")
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("factor/browser input serialized")
	}
	if _, err := json.Marshal(mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeUnknown}); err == nil {
		t.Fatal("completion result exported implicitly")
	}
}

func TestTOTPCompletionRejectsEmptyURLFragments(t *testing.T) {
	for _, field := range []string{"origin", "callback"} {
		t.Run(field, func(t *testing.T) {
			request := totpRequestFixture(t)
			if field == "origin" {
				request.Origin += "#"
			} else {
				request.Callback += "#"
			}
			if request.Validate() == nil {
				t.Fatal("fragment delimiter accepted at fragment-free browser boundary")
			}
		})
	}
}
