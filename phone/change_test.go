package phone_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

func phoneChangeRequest(t *testing.T) phone.ChangeRequestSpec {
	t.Helper()
	enrollment := enrollmentRequest(t)
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := policy.Canonicalize(context.Background(), "+12025550124")
	if err != nil {
		t.Fatal(err)
	}
	return phone.ChangeRequestSpec{Enrollment: enrollment, PreviousNumber: previous,
		IdentifierID: "original-phone", ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2}
}

func phoneUpdateRequest(t *testing.T) phone.UpdateRequestSpec {
	t.Helper()
	v := verificationRequest(t)
	proof := enrollmentRequest(t).Proof
	proof.Action = "identity.phone.update"
	v.Caller.Request.Action = "identity.phone.update"
	key, err := identity.NewIdempotencyKey([]byte("original-phone-update"))
	if err != nil {
		t.Fatal(err)
	}
	return phone.UpdateRequestSpec{TenantID: v.TenantID, UserID: v.UserID,
		Caller: v.Caller, Flow: v.Flow, SendCommandID: v.SendCommandID, Code: v.Code,
		CSRFToken: v.CSRFToken, Proof: proof, Reason: "user-request", IdempotencyKey: key}
}

func TestPhoneUpdateRequiresDistinctFreshActionAndOriginalSession(t *testing.T) {
	base := phoneUpdateRequest(t)
	if _, err := phone.NewUpdateRequest(base); err != nil {
		t.Fatal("valid replacement completion rejected", err)
	}
	for name, alter := range map[string]func(*phone.UpdateRequestSpec){
		"no-flow":               func(r *phone.UpdateRequestSpec) { r.Flow = otp.SendFlow{} },
		"bad-send":              func(r *phone.UpdateRequestSpec) { r.SendCommandID = "invalid" },
		"foreign-tenant":        func(r *phone.UpdateRequestSpec) { r.TenantID = "foreign" },
		"foreign-user":          func(r *phone.UpdateRequestSpec) { r.UserID = "foreign" },
		"foreign-resource":      func(r *phone.UpdateRequestSpec) { r.Caller.Request.Resource.ID = "foreign" },
		"wrong-action":          func(r *phone.UpdateRequestSpec) { r.Caller.Request.Action = "identity.phone.verify" },
		"send-proof":            func(r *phone.UpdateRequestSpec) { r.Proof.Action = "identity.phone.send-verification" },
		"foreign-proof-subject": func(r *phone.UpdateRequestSpec) { r.Proof.Proof.Subject = "foreign" },
		"foreign-proof-session": func(r *phone.UpdateRequestSpec) { r.Proof.SessionID = "another-session" },
		"no-proof":              func(r *phone.UpdateRequestSpec) { r.Proof = auth.ReauthenticationProof{} },
		"no-key":                func(r *phone.UpdateRequestSpec) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"wrong-method":          func(r *phone.UpdateRequestSpec) { r.Proof.Proof.Method = "otp" },
		"wrong-assurance":       func(r *phone.UpdateRequestSpec) { r.Proof.Proof.Assurance = auth.AssuranceMultiFactor },
		"no-reason":             func(r *phone.UpdateRequestSpec) { r.Reason = "" },
		"arbitrary-reason":      func(r *phone.UpdateRequestSpec) { r.Reason = "user asked to change phone" },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Caller = base.Caller.Clone()
			alter(&r)
			if _, err := phone.NewUpdateRequest(r); err == nil {
				t.Fatal("invalid replacement completion accepted")
			}
		})
	}
	if _, err := (phone.UpdateRequest{}).Bindings(); err == nil {
		t.Fatal("zero replacement completion accepted")
	}
}

func TestPhoneUpdateFreezesAndRedactsSubmissionCustody(t *testing.T) {
	spec := phoneUpdateRequest(t)
	spec.Caller.Request.Subject.Groups = []authorization.SubjectID{"original"}
	r, err := phone.NewUpdateRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Caller.Request.Subject.Groups[0] = "changed"
	got, err := r.Bindings()
	if err != nil || got.Caller.Request.Subject.Groups[0] != "original" || got.Proof != spec.Proof ||
		got.SendCommandID != spec.SendCommandID || got.CSRFToken != spec.CSRFToken {
		t.Fatal("completion lost or aliased original custody", err)
	}
	got.Caller.Request.Subject.Groups[0] = "changed-again"
	again, err := r.Bindings()
	if err != nil || again.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("projection mutated completion custody", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
		text := fmt.Sprintf(format, struct{ private any }{r})
		for _, sensitive := range []string{"123456", string(spec.SendCommandID), spec.Proof.SessionID, string(spec.Proof.Proof.ID)} {
			if strings.Contains(text, sensitive) {
				t.Fatal("nested diagnostic disclosed replacement submission")
			}
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("implicit replacement submission export accepted")
	}
}

func TestPhoneChangeRetainsDistinctExactVerifiedPredecessor(t *testing.T) {
	base := phoneChangeRequest(t)
	request, err := phone.NewChangeRequest(base)
	if err != nil {
		t.Fatal("valid original replacement request rejected", err)
	}
	got, err := request.Bindings()
	if err != nil || got.IdentifierID != base.IdentifierID ||
		!got.PreviousNumber.Equal(base.PreviousNumber) || !got.Enrollment.Number.Equal(base.Enrollment.Number) ||
		got.ExpectedIdentifierVersion != 2 || got.ExpectedVerificationVersion != 2 ||
		got.Enrollment.Proof != base.Enrollment.Proof || got.Enrollment.IdempotencyKey != base.Enrollment.IdempotencyKey {
		t.Fatal("replacement lost original custody or versions", err)
	}
	for name, mutate := range map[string]func(*phone.ChangeRequestSpec){
		"no-previous":           func(r *phone.ChangeRequestSpec) { r.PreviousNumber = phone.Number{} },
		"same-number":           func(r *phone.ChangeRequestSpec) { r.PreviousNumber = r.Enrollment.Number },
		"no-identifier":         func(r *phone.ChangeRequestSpec) { r.IdentifierID = "" },
		"bad-identifier":        func(r *phone.ChangeRequestSpec) { r.IdentifierID = "original phone" },
		"zero-version":          func(r *phone.ChangeRequestSpec) { r.ExpectedIdentifierVersion = 0 },
		"zero-verification":     func(r *phone.ChangeRequestSpec) { r.ExpectedVerificationVersion = 0 },
		"overflow-version":      func(r *phone.ChangeRequestSpec) { r.ExpectedIdentifierVersion = ^uint64(0) },
		"overflow-verification": func(r *phone.ChangeRequestSpec) { r.ExpectedVerificationVersion = ^uint64(0) },
		"wrong-action":          func(r *phone.ChangeRequestSpec) { r.Enrollment.Caller.Request.Action = "identity.phone.update" },
		"wrong-proof":           func(r *phone.ChangeRequestSpec) { r.Enrollment.Proof.Action = "identity.phone.update" },
		"wrong-resource":        func(r *phone.ChangeRequestSpec) { r.Enrollment.Caller.Request.Resource.ID = "another-user" },
		"no-key":                func(r *phone.ChangeRequestSpec) { r.Enrollment.IdempotencyKey = identity.IdempotencyKey{} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Enrollment.Caller = base.Enrollment.Caller.Clone()
			mutate(&candidate)
			if _, err := phone.NewChangeRequest(candidate); err == nil {
				t.Fatal("invalid replacement request accepted")
			}
		})
	}
	if _, err := (phone.ChangeRequest{}).Bindings(); err == nil {
		t.Fatal("zero replacement request accepted")
	}
}

func TestPhoneChangeFreezesAndRedactsOriginalRequest(t *testing.T) {
	spec := phoneChangeRequest(t)
	spec.Enrollment.Caller.Request.Subject.Groups = []authorization.SubjectID{"original"}
	request, err := phone.NewChangeRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Enrollment.Caller.Request.Subject.Groups[0] = "changed"
	first, err := request.Bindings()
	if err != nil || first.Enrollment.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("construction retained mutable caller alias", err)
	}
	first.Enrollment.Caller.Request.Subject.Groups[0] = "changed-again"
	second, err := request.Bindings()
	if err != nil || second.Enrollment.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("projection changed frozen caller", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
		text := fmt.Sprintf(verb, struct{ private any }{request})
		for _, secret := range []string{"+12025550123", "+12025550124", "original-phone", spec.Enrollment.Session.Token()} {
			if strings.Contains(text, secret) {
				t.Fatal("nested diagnostic exposed replacement custody")
			}
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("implicit request export accepted")
	}
}
