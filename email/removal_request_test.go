package email_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

func TestAddressRemovalRequiresOriginalProofAndExplicitDisposition(t *testing.T) {
	base := managedSendRequest(t)
	base.Caller.Request.Action = "identity.email.address-remove"
	base.Primary.Proof.Action = "identity.email.address-remove"
	r := email.AddressRemoveRequest{
		TenantID: base.TenantID, AddressID: "address", ExpectedIdentifierVersion: 2,
		ExpectedVerificationVersion: 3, Reason: "user-requested",
		PrimaryDisposition:  email.LeavePrimaryUnassigned,
		RecoveryDisposition: email.PreserveVerifiedEmailRecovery,
		IdempotencyKey:      base.IdempotencyKey, Primary: base.Primary,
		Caller: base.Caller, Network: base.Network,
	}
	if err := r.Validate(); err != nil {
		t.Fatal("selected bounded removal denied", err)
	}
	for name, alter := range map[string]func(*email.AddressRemoveRequest){
		"target":       func(r *email.AddressRemoveRequest) { r.AddressID = "" },
		"version":      func(r *email.AddressRemoveRequest) { r.ExpectedIdentifierVersion = 0 },
		"verification": func(r *email.AddressRemoveRequest) { r.ExpectedVerificationVersion = ^uint64(0) },
		"reason":       func(r *email.AddressRemoveRequest) { r.Reason = "mailbox@example.test" },
		"reason-size":  func(r *email.AddressRemoveRequest) { r.Reason = identity.PolicyReason(strings.Repeat("a", 65)) },
		"primary":      func(r *email.AddressRemoveRequest) { r.PrimaryDisposition = 0 },
		"recovery":     func(r *email.AddressRemoveRequest) { r.RecoveryDisposition = 0 },
		"tenant":       func(r *email.AddressRemoveRequest) { r.TenantID = "other" },
		"subject":      func(r *email.AddressRemoveRequest) { r.Caller.Request.Subject.ID = "other" },
		"proof":        func(r *email.AddressRemoveRequest) { r.Primary.Proof.Action = "identity.email.change-request" },
		"key":          func(r *email.AddressRemoveRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"network":      func(r *email.AddressRemoveRequest) { r.Network = "untrusted" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			candidate.Caller = r.Caller.Clone()
			alter(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("unbound or unspecified removal admitted")
			}
		})
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("implicit removal input export")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, r); !strings.Contains(out, "redacted") || strings.Contains(out, "user-requested") {
			t.Fatal("removal diagnostics disclosed original custody")
		}
	}
}
