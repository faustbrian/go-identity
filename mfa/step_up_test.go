package mfa_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func authenticatedTOTPRequest(t *testing.T) mfa.TotpVerifyRequest {
	t.Helper()
	regenerate := regenerationRequest()
	code, _ := auth.NewOneTimeCode("123456")
	csrf, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	caller := regenerate.Caller.Clone()
	caller.Request.Action = "identity.mfa.totp-verify"
	return mfa.TotpVerifyRequest{TenantID: regenerate.TenantID, CommandID: "AAAAAAAAAAAAAAAAAAAAAw", FactorID: "AAAAAAAAAAAAAAAAAAAABA", Code: code, Caller: caller, Origin: regenerate.Origin, Network: regenerate.Network, StepUp: &mfa.TOTPAuthenticatedStepUp{Session: regenerate.Session, CSRFToken: csrf, Purpose: "identity.mfa.recovery-regenerate"}}
}

func TestAuthenticatedTOTPIsDisjointFromLoginAndEnrollment(t *testing.T) {
	r := authenticatedTOTPRequest(t)
	if r.Validate() != nil {
		t.Fatal("bounded active-session TOTP request rejected")
	}
	for _, change := range []func(*mfa.TotpVerifyRequest){
		func(r *mfa.TotpVerifyRequest) { r.StepUp.Purpose = "identity.password.change" },
		func(r *mfa.TotpVerifyRequest) { r.StepUp.Session = auth.BearerCredential{} },
		func(r *mfa.TotpVerifyRequest) { r.StepUp.CSRFToken = session.CSRFToken{} },
		func(r *mfa.TotpVerifyRequest) { r.TrustDevice = true },
		func(r *mfa.TotpVerifyRequest) { r.ChallengeID = "AAAAAAAAAAAAAAAAAAAABQ" },
		func(r *mfa.TotpVerifyRequest) { r.PreAuthID = "AAAAAAAAAAAAAAAAAAAABQ" },
		func(r *mfa.TotpVerifyRequest) { r.Cookie = r.StepUp.Session },
		func(r *mfa.TotpVerifyRequest) { r.Callback = "https://app.example/callback" },
		func(r *mfa.TotpVerifyRequest) { r.Device = "supplied-device" },
		func(r *mfa.TotpVerifyRequest) {
			r.Enrollment = &mfa.TOTPEnrollmentConfirmation{Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken}
		},
		func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Subject.Kind = "" },
		func(r *mfa.TotpVerifyRequest) { r.Caller.Request.Resource.ID = "other-user" },
		func(r *mfa.TotpVerifyRequest) { r.Code = auth.OneTimeCode{} },
		func(r *mfa.TotpVerifyRequest) { r.FactorID = "" },
		func(r *mfa.TotpVerifyRequest) { r.Origin += "#" },
	} {
		bad := r
		step := *r.StepUp
		bad.StepUp = &step
		bad.Caller = r.Caller.Clone()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("mixed or unauthenticated step-up input admitted")
		}
	}
	// Actual login proof must not become active-session proof merely because
	// the caller also supplies step-up custody.
	login := totpRequestFixture(t)
	login.StepUp = r.StepUp
	if login.Validate() == nil || login.Proof == (capability.Proof{}) {
		t.Fatal("login proof accepted in active-session variant")
	}
}

func TestContinuationProofPreservesOriginalSessionActionAndProjection(t *testing.T) {
	r := regenerationRequest()
	original := auth.ReauthenticationProof{Proof: r.FactorProof, SessionID: "source-session", SessionVersion: 7, Action: string(r.FactorProof.Purpose)}
	p, err := mfa.NewContinuationProof(original)
	if err != nil || p.Bindings() != original {
		t.Fatal("original action/session proof was changed")
	}
	for _, change := range []func(*auth.ReauthenticationProof){
		func(p *auth.ReauthenticationProof) { p.SessionID = "" },
		func(p *auth.ReauthenticationProof) { p.SessionVersion = 0 },
		func(p *auth.ReauthenticationProof) { p.Action = "identity.mfa.disable" },
		func(p *auth.ReauthenticationProof) { p.Proof.Method = "recovery-code" },
		func(p *auth.ReauthenticationProof) { p.Proof.Method = "password" },
		func(p *auth.ReauthenticationProof) { p.Proof.Assurance = auth.AssuranceSingleFactor },
		func(p *auth.ReauthenticationProof) { p.Proof.ExpiresAt = p.Proof.IssuedAt },
	} {
		bad := original
		change(&bad)
		if _, err := mfa.NewContinuationProof(bad); err == nil {
			t.Fatal("malformed or ineligible proof projection accepted")
		}
	}
	if (mfa.ContinuationProof{}).Bindings() != (auth.ReauthenticationProof{}) {
		t.Fatal("zero proof fabricated authority")
	}
	// The value carries metadata, not a session credential or verified signature.
	// Its existence cannot authorize regeneration; native provenance/use still
	// has to be checked against the original issuance transaction.
	for _, value := range []any{p, authenticatedTOTPRequest(t).StepUp, mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, StepUpProof: p}} {
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("step-up diagnostics traversed custody")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit step-up export accepted")
		}
	}
}
