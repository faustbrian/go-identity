package email_test

import (
	"encoding/json"
	"fmt"
	"github.com/faustbrian/go-authorization/v3"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

func TestAddressRemovalKeepsExplicitTargetSeparateFromFreshActor(t *testing.T) {
	base := managedSendRequest(t)
	base.Caller.Request.Action = "identity.email.address-remove"
	base.Primary.Proof.Action = "identity.email.address-remove"
	r := email.AddressRemoveRequest{TenantID: base.TenantID, TargetSubjectID: "target-user", AddressID: "target-address", ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3, Reason: "admin-requested", PrimaryDisposition: email.LeavePrimaryUnassigned, RecoveryDisposition: email.PreserveVerifiedEmailRecovery, IdempotencyKey: base.IdempotencyKey, Primary: base.Primary, Caller: base.Caller, Network: base.Network}
	r.Caller.Request.Resource.ID = authorization.ResourceID(r.TargetSubjectID)
	if err := r.Validate(); err != nil {
		t.Fatal("explicit administrative target lost its independent authenticated actor", err)
	}
	for _, mode := range []string{"omitted-target", "actor-substitution", "wrong-resource", "service-actor", "malformed-target"} {
		bad := r
		switch mode {
		case "omitted-target":
			bad.TargetSubjectID = ""
		case "actor-substitution":
			bad.Primary.Proof.Proof.Subject = string(r.TargetSubjectID)
		case "wrong-resource":
			bad.Caller.Request.Resource.ID = "other-target"
		case "service-actor":
			bad.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
		case "malformed-target":
			bad.TargetSubjectID = "invalid target"
		}
		if bad.Validate() == nil {
			t.Fatal("target selector granted or substituted authority", mode)
		}
	}
}

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
	selected := r
	selected.PrimaryDisposition = email.ReplacePrimaryWithVerifiedEmail
	selected.ReplacementPrimary = identity.IdentifierPrimarySelection{ID: "remaining", ExpectedIdentifierVersion: 5, ExpectedVerificationVersion: 7}
	if selected.Validate() != nil {
		t.Fatal("explicit bounded replacement denied")
	}
	for _, mode := range []string{"missing", "self", "zero-version", "old-disposition"} {
		bad := selected
		switch mode {
		case "missing":
			bad.ReplacementPrimary = identity.IdentifierPrimarySelection{}
		case "self":
			bad.ReplacementPrimary.ID = bad.AddressID
		case "zero-version":
			bad.ReplacementPrimary.ExpectedVerificationVersion = 0
		case "old-disposition":
			bad.PrimaryDisposition = email.LeavePrimaryUnassigned
		}
		if bad.Validate() == nil {
			t.Fatal("replacement intent lost exact disposition", mode)
		}
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
