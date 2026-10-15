package mfa_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func recoveryRequestFixture(t *testing.T) mfa.RecoveryUseRequest {
	t.Helper()
	base := totpRequestFixture(t)
	code, err := auth.NewRecoveryCode("synthetic-recovery-code")
	if err != nil {
		t.Fatal(err)
	}
	base.Caller.Request.Action = "identity.mfa.recovery-use"
	return mfa.RecoveryUseRequest{TenantID: base.TenantID, CommandID: base.CommandID, ContinuationID: mfa.ContinuationID(base.ChallengeID), RecoveryCode: code, Proof: base.Proof, PreAuthID: base.PreAuthID, Cookie: base.Cookie, Caller: base.Caller, Origin: base.Origin, Callback: base.Callback, Network: base.Network, Device: base.Device}
}

func TestRecoveryCompletionRequiresOriginalBoundedBrowserCustody(t *testing.T) {
	r := recoveryRequestFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*mfa.RecoveryUseRequest){
		func(r *mfa.RecoveryUseRequest) { r.TenantID = "" },
		func(r *mfa.RecoveryUseRequest) { r.CommandID = "" },
		func(r *mfa.RecoveryUseRequest) { r.CommandID = identity.CommandID(r.ContinuationID) },
		func(r *mfa.RecoveryUseRequest) { r.ContinuationID = "bad" },
		func(r *mfa.RecoveryUseRequest) { r.RecoveryCode = auth.RecoveryCode{} },
		func(r *mfa.RecoveryUseRequest) { r.Proof = capability.Proof{} },
		func(r *mfa.RecoveryUseRequest) { r.PreAuthID = "" },
		func(r *mfa.RecoveryUseRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *mfa.RecoveryUseRequest) { r.Caller.Request.Action = "identity.mfa.totp-verify" },
		func(r *mfa.RecoveryUseRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *mfa.RecoveryUseRequest) { r.Caller.Request.Resource.ID = "foreign" },
		func(r *mfa.RecoveryUseRequest) { r.Caller.PolicyRevision = 0 },
		func(r *mfa.RecoveryUseRequest) { r.Origin += "#" },
		func(r *mfa.RecoveryUseRequest) { r.Callback += "#" },
		func(r *mfa.RecoveryUseRequest) { r.Callback = "https://user:password@app.test/login" },
		func(r *mfa.RecoveryUseRequest) { r.Network = "not-an-ip" },
		func(r *mfa.RecoveryUseRequest) { r.Device = strings.Repeat("x", 256) },
	} {
		changed := r
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("foreign or incomplete recovery request accepted")
		}
	}
	if fmt.Sprintf("%#v", r) != "mfa.RecoveryUseRequest(redacted)" {
		t.Fatal("recovery input disclosed")
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("recovery code/browser custody serialized")
	}
	if _, err := json.Marshal(mfa.RecoveryUseResult{Outcome: identity.CommitOutcomeUnknown, RecoveryRequired: true}); err == nil {
		t.Fatal("recovery result implicitly exported")
	}
}
