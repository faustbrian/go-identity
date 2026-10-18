package email_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
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

func TestVerificationSigninPendingMFAIsNotAnAuthenticatedSession(t *testing.T) {
	q := verificationRecoveryQuery(t)
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	challenge, _ := identity.NewCommandID()
	proof := confirmationRequest(t).Token
	result := email.VerificationSigninResult{Verification: email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Address: verifiedProjection(t, q)}, Issuance: session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeCommitted}, Recovery: identity.RecoveryQuery{CommandID: id, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, RecordID: string(q.CommandID), OperationID: "identity.email.verification-signin"}, Challenge: &email.VerificationMFAChallenge{ID: challenge, Method: "totp", ExpiresAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Proof: proof}}
	if result.Validate() != nil {
		t.Fatal("well-formed pending-only result rejected")
	}
	for _, change := range []func(*email.VerificationSigninResult){
		func(r *email.VerificationSigninResult) { r.Challenge.ID = r.Recovery.CommandID },
		func(r *email.VerificationSigninResult) { r.Challenge.ID = q.CommandID },
		func(r *email.VerificationSigninResult) { r.Challenge.Method = "otp" },
		func(r *email.VerificationSigninResult) {
			r.Challenge.ExpiresAt = r.Challenge.ExpiresAt.Add(time.Nanosecond)
		},
		func(r *email.VerificationSigninResult) { r.Issuance.Replayed = true },
		func(r *email.VerificationSigninResult) { r.Issuance.Cookie.Name = "premature-session" },
		func(r *email.VerificationSigninResult) { r.Issuance.Token, _ = session.NewToken(32) },
		func(r *email.VerificationSigninResult) { r.CSRFToken, _ = session.NewCSRFToken() },
		func(r *email.VerificationSigninResult) { r.Issuance.CommitOutcome = identity.CommitOutcomeUnknown },
	} {
		bad := result
		c := *result.Challenge
		bad.Challenge = &c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("pending challenge accepted conflicting origin, session custody or outcome")
		}
	}
	replay := result
	c := *result.Challenge
	replay.Challenge = &c
	replay.Issuance.Replayed = true
	replay.Challenge.Proof = capability.Proof{}
	if replay.Validate() != nil {
		t.Fatal("credential-free pending replay metadata rejected")
	}
	for _, value := range []any{result, *result.Challenge} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit pending credential export permitted")
		}
	}
	if fmt.Sprintf("%+v", *result.Challenge) != "email.VerificationMFAChallenge(redacted)" {
		t.Fatal("challenge formatting disclosed custody")
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
