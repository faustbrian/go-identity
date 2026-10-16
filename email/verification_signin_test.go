package email_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/session"
)

func TestVerificationSigninRequiresExplicitOriginalBrowserCustody(t *testing.T) {
	confirmation := confirmationRequest(t)
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	r := email.VerificationSigninRequest{Confirmation: confirmation, Browser: auth.NewBearerCredential(wire), Origin: "https://app.example.test", Device: "original-browser"}
	if err := r.Validate(); err != nil {
		t.Fatal("bounded explicit signin input denied", err)
	}
	for _, change := range []func(*email.VerificationSigninRequest){
		func(r *email.VerificationSigninRequest) { r.Browser = auth.BearerCredential{} },
		func(r *email.VerificationSigninRequest) { r.Origin = "https://app.example.test/path" },
		func(r *email.VerificationSigninRequest) { r.Origin = "http://app.example.test" },
		func(r *email.VerificationSigninRequest) { r.Device = "" },
		func(r *email.VerificationSigninRequest) { r.Device = strings.Repeat("x", 257) },
		func(r *email.VerificationSigninRequest) {
			r.Confirmation.Caller.Request.Action = "identity.email.change-confirm"
		},
	} {
		bad := r
		bad.Confirmation.Caller = r.Confirmation.Caller.Clone()
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("missing or cross-profile custody admitted")
		}
	}
	if _, err := json.Marshal(r); err == nil || strings.Contains(fmt.Sprintf("%+v", r), wire) {
		t.Fatal("signin input disclosed browser custody")
	}
	if (email.VerificationSigninResult{}).Validate() == nil {
		t.Fatal("unobserved verification became signin")
	}
}

func TestVerificationSigninResultSeparatesKnownVerificationFromLogin(t *testing.T) {
	q := verificationRecoveryQuery(t)
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	result := email.VerificationSigninResult{
		Verification: email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Address: verifiedProjection(t, q)},
		Issuance:     session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeUnknown},
		Recovery:     identity.RecoveryQuery{CommandID: id, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, RecordID: string(q.CommandID), OperationID: "identity.email.verification-signin"},
	}
	if err := result.Validate(); err != nil {
		t.Fatal("known verification plus unknown login lost", err)
	}
	for _, mutate := range []func(*email.VerificationSigninResult){
		func(r *email.VerificationSigninResult) { r.Recovery.RecordID = q.RecordID },
		func(r *email.VerificationSigninResult) { r.Recovery.UserID = "foreign-user" },
		func(r *email.VerificationSigninResult) { r.Recovery.TenantID = "foreign-tenant" },
		func(r *email.VerificationSigninResult) { r.Recovery.ActorID = "foreign-actor" },
		func(r *email.VerificationSigninResult) { r.Recovery.OperationID = "identity.magic-link.consume" },
		func(r *email.VerificationSigninResult) {
			r.Verification.Replayed = true
			r.Verification.Address = identity.IdentifierProjection{}
		},
		func(r *email.VerificationSigninResult) {
			r.Verification.Outcome = identity.CommitOutcomeUnknown
			r.Verification.Address = identity.IdentifierProjection{}
		},
		func(r *email.VerificationSigninResult) { r.Issuance.Cookie.Name = "uncommitted-cookie" },
		func(r *email.VerificationSigninResult) {
			r.Issuance.Token, _ = session.ParseToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		},
	} {
		bad := result
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("cross-profile outcome or premature credential admitted")
		}
	}
}
