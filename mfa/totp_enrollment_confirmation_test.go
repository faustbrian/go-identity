package mfa_test

import (
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func enrollmentConfirmationFixture(t *testing.T) mfa.TotpVerifyRequest {
	t.Helper()
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	return mfa.TotpVerifyRequest{TenantID: "tenant-a", CommandID: "AAAAAAAAAAAAAAAAAAAAAg", FactorID: "AAAAAAAAAAAAAAAAAAAAAQ", Code: code, Origin: "https://app.test", Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-a", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}}, Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: auth.NewBearerCredential(strings.Repeat("A", 43)), CSRFToken: csrf}}
}

func TestTOTPVerificationExplicitEnrollmentVariantDoesNotRequireLoginChild(t *testing.T) {
	r := enrollmentConfirmationFixture(t)
	for range 2 {
		if err := r.Validate(); err != nil {
			t.Fatal("explicit authenticated enrollment confirmation denied")
		}
	}
	if _, err := r.Enrollment.CSRFToken.Reveal(); err != nil {
		t.Fatal("confirmation validation consumed borrowed synchronizer")
	}
	for _, change := range []func(*mfa.TotpVerifyRequest){
		func(r *mfa.TotpVerifyRequest) { r.Enrollment.Session = auth.BearerCredential{} },
		func(r *mfa.TotpVerifyRequest) { r.Enrollment.CSRFToken = session.CSRFToken{} },
		func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Resource.ID = "foreign" },
		func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		func(r *mfa.TotpVerifyRequest) { r.ChallengeID = "AAAAAAAAAAAAAAAAAAAAAw" },
		func(r *mfa.TotpVerifyRequest) { r.Callback = "https://app.test/login" },
		func(r *mfa.TotpVerifyRequest) { r.Cookie = auth.NewBearerCredential(strings.Repeat("A", 43)) },
		func(r *mfa.TotpVerifyRequest) { r.CommandID = "AAAAAAAAAAAAAAAAAAAAAQ" },
	} {
		candidate := r
		candidate.Caller = r.Caller.Clone()
		copy := *r.Enrollment
		candidate.Enrollment = &copy
		change(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("mixed login/enrollment variant or foreign confirmation admitted")
		}
	}
	login := totpRequestFixture(t)
	login.Enrollment = r.Enrollment
	if login.Validate() == nil {
		t.Fatal("login child accepted as enrollment custody")
	}
}
