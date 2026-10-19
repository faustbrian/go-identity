package phone_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
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
