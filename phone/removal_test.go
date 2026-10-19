package phone_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/phone"
)

func removalRequest(t *testing.T) phone.RemoveRequestSpec {
	t.Helper()
	enrollment := enrollmentRequest(t)
	enrollment.Caller.Request.Action = "identity.phone.remove"
	enrollment.Proof.Action = "identity.phone.remove"
	return phone.RemoveRequestSpec{
		TenantID: enrollment.TenantID, UserID: enrollment.UserID,
		Number: enrollment.Number, IdentifierID: "verified-phone",
		ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2,
		Reason: "user-request", Session: enrollment.Session, Proof: enrollment.Proof,
		Caller: enrollment.Caller, CSRFToken: enrollment.CSRFToken,
		IdempotencyKey: enrollment.IdempotencyKey, Network: enrollment.Network,
	}
}

func TestPhoneRemovalRequiresExactAuthenticatedSelfIntent(t *testing.T) {
	base := removalRequest(t)
	request, err := phone.NewRemoveRequest(base)
	if err != nil {
		t.Fatal("valid original bearer removal rejected", err)
	}
	got, err := request.Bindings()
	if err != nil || got.IdentifierID != base.IdentifierID || !got.Number.Equal(base.Number) || got.Proof != base.Proof || got.ExpectedIdentifierVersion != 2 || got.ExpectedVerificationVersion != 2 {
		t.Fatal("original removal custody changed", err)
	}
	for name, change := range map[string]func(*phone.RemoveRequestSpec){
		"tenant":               func(r *phone.RemoveRequestSpec) { r.TenantID = "foreign" },
		"subject":              func(r *phone.RemoveRequestSpec) { r.UserID = "foreign" },
		"phone":                func(r *phone.RemoveRequestSpec) { r.Number = phone.Number{} },
		"identifier":           func(r *phone.RemoveRequestSpec) { r.IdentifierID = "" },
		"version":              func(r *phone.RemoveRequestSpec) { r.ExpectedIdentifierVersion = 0 },
		"verification-version": func(r *phone.RemoveRequestSpec) { r.ExpectedVerificationVersion = 0 },
		"overflow":             func(r *phone.RemoveRequestSpec) { r.ExpectedIdentifierVersion = ^uint64(0) },
		"reason":               func(r *phone.RemoveRequestSpec) { r.Reason = "not free text" },
		"reason-large":         func(r *phone.RemoveRequestSpec) { r.Reason = identity.PolicyReason(strings.Repeat("x", 65)) },
		"action":               func(r *phone.RemoveRequestSpec) { r.Caller.Request.Action = "identity.phone.verify" },
		"proof-action":         func(r *phone.RemoveRequestSpec) { r.Proof.Action = "identity.phone.send-verification" },
		"proof-purpose":        func(r *phone.RemoveRequestSpec) { r.Proof.Proof.Purpose = "identity.phone.signin" },
		"proof-session":        func(r *phone.RemoveRequestSpec) { r.Proof.SessionVersion = 0 },
		"proof-subject":        func(r *phone.RemoveRequestSpec) { r.Proof.Proof.Subject = "foreign" },
		"proof-assurance":      func(r *phone.RemoveRequestSpec) { r.Proof.Proof.Assurance = 0 },
		"key":                  func(r *phone.RemoveRequestSpec) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"network":              func(r *phone.RemoveRequestSpec) { r.Network = "localhost" },
		"network-zone":         func(r *phone.RemoveRequestSpec) { r.Network = "fe80::1%en0" },
		"unspecified-network":  func(r *phone.RemoveRequestSpec) { r.Network = "0.0.0.0" },
		"caller-size": func(r *phone.RemoveRequestSpec) {
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Caller = base.Caller.Clone()
			change(&candidate)
			if _, err := phone.NewRemoveRequest(candidate); err == nil {
				t.Fatal("invalid removal scope accepted")
			}
		})
	}
	if _, err := (phone.RemoveRequest{}).Bindings(); err == nil {
		t.Fatal("zero original removal custody accepted")
	}
}

func TestPhoneRemovalFreezesCallerAndHidesNestedCustody(t *testing.T) {
	spec := removalRequest(t)
	spec.Caller.Request.Subject.Groups = []authorization.SubjectID{"original"}
	request, err := phone.NewRemoveRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Caller.Request.Subject.Groups[0] = "changed"
	first, err := request.Bindings()
	if err != nil || first.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("caller changed after construction", err)
	}
	first.Caller.Request.Subject.Groups[0] = "changed"
	second, err := request.Bindings()
	if err != nil || second.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("projection modified original custody", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
		text := fmt.Sprintf(verb, struct{ private any }{request})
		for _, secret := range []string{"+12025550123", spec.Session.Token(), string(spec.Proof.Proof.ID), "verified-phone"} {
			if strings.Contains(text, secret) {
				t.Fatal("nested diagnostics exposed original removal custody")
			}
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("implicit removal custody serialization accepted")
	}
}
