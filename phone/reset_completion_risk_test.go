package phone_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identity/phone"
)

// Structural custody only: this local signature is not native issuance or
// authority to request completion evidence for an account.
func TestPhoneResetCompletionRiskUsesOriginalCapabilityWithoutSelectedUser(t *testing.T) {
	base := initiationRiskSpec(t)
	signer, err := capability.NewHMACSHA256Signer("fixture", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	wire, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://identity.test", Audiences: []string{"phone-reset"}, Tenant: "tenant", Subject: "user", Operation: "identity.phone.password-reset-complete", Resource: "identity.password/password", ID: "structural-fixture", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	base.Caller.Request.Action = "identity.phone.password-reset-complete"
	spec := phone.PasswordResetCompletionRiskRequestSpec{TenantID: base.TenantID, CommandID: base.CommandID, IssuanceCommandID: base.IssuanceCommandID, Flow: base.Flow, ResetCapability: proof, Caller: base.Caller, Origin: base.Origin, Network: base.Network, Device: base.Device}
	r, err := phone.NewPasswordResetCompletionRiskRequest(spec)
	if err != nil {
		t.Fatal("completion risk requires original browser/capability, not an invented reference", err)
	}
	spec.Caller.Request.Action = "identity.phone.password-reset-request"
	got, err := r.Bindings()
	wantDigest, _ := proof.CommandDigest([32]byte{1}, "test", 4096)
	gotDigest, digestErr := got.ResetCapability.CommandDigest([32]byte{1}, "test", 4096)
	if err != nil || digestErr != nil || got.Caller.Request.Action != "identity.phone.password-reset-complete" || gotDigest != wantDigest {
		t.Fatal("completion risk lost original borrowed custody", err)
	}
	if _, err = json.Marshal(r); err == nil {
		t.Fatal("completion risk serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", struct{ private any }{r}), wire) {
		t.Fatal("nested completion risk disclosed proof")
	}
	for _, change := range []func(*phone.PasswordResetCompletionRiskRequestSpec){
		func(s *phone.PasswordResetCompletionRiskRequestSpec) { s.Caller.Request.Resource.ID = "chosen-user" },
		func(s *phone.PasswordResetCompletionRiskRequestSpec) {
			s.Caller.Request.Action = "identity.phone.password-reset-request"
		},
		func(s *phone.PasswordResetCompletionRiskRequestSpec) { s.IssuanceCommandID = s.CommandID },
		func(s *phone.PasswordResetCompletionRiskRequestSpec) { s.ResetCapability = capability.Proof{} },
		func(s *phone.PasswordResetCompletionRiskRequestSpec) { s.Network = "2001:0db8::1" },
	} {
		candidate := got
		candidate.Caller = got.Caller.Clone()
		change(&candidate)
		if _, err := phone.NewPasswordResetCompletionRiskRequest(candidate); err == nil {
			t.Fatal("foreign completion-risk input admitted")
		}
	}
	if _, err := (phone.PasswordResetCompletionRiskRequest{}).Bindings(); err == nil {
		t.Fatal("zero completion-risk request projected")
	}
	if err = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Bindings(); err == nil {
		t.Fatal("destroyed borrowed capability remained usable")
	}
}
