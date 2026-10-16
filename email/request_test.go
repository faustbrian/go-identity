package email_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

func managedSendRequest(t *testing.T) email.VerificationSendRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-email-request-key"))
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse("https://app.example.test/done")
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant", Subject: "user", Purpose: "identity.password.verify", Audience: "email", Method: "password", Assurance: auth.AssuranceSingleFactor, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, SessionID: "session", SessionVersion: 1, Action: "identity.email.verification-send"}
	return email.VerificationSendRequest{TenantID: "tenant", Address: "New@example.test", Callback: *callback, IdempotencyKey: key, Primary: email.RequestPrimary{Session: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"), Proof: proof}, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.email.verification-send", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}, Network: "192.0.2.1"}
}

func TestEmailKeyedRequestHasClosedSelfScope(t *testing.T) {
	r := managedSendRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid bounded original input", err)
	}
	for name, change := range map[string]func(*email.VerificationSendRequest){
		"tenant":       func(r *email.VerificationSendRequest) { r.TenantID = "foreign" },
		"actor":        func(r *email.VerificationSendRequest) { r.Caller.Request.Subject.ID = "other" },
		"target":       func(r *email.VerificationSendRequest) { r.SubjectID = "other" },
		"proof-action": func(r *email.VerificationSendRequest) { r.Primary.Proof.Action = "identity.email.change-request" },
		"callback":     func(r *email.VerificationSendRequest) { r.Callback.Scheme = "http" },
		"address":      func(r *email.VerificationSendRequest) { r.Address = "" },
		"key":          func(r *email.VerificationSendRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"network":      func(r *email.VerificationSendRequest) { r.Network = "spoofed address" },
		"bearer":       func(r *email.VerificationSendRequest) { r.Primary.Session = auth.BearerCredential{} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			candidate.Caller = r.Caller.Clone()
			change(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("unbound request admitted")
			}
		})
	}
	resend := r
	resend.AddressID = "existing"
	resend.Address = ""
	if err := resend.Validate(); err != nil {
		t.Fatal("exact resend may resolve stored destination", err)
	}
	change := email.ChangeRequestRequest{TenantID: r.TenantID, NewAddress: r.Address, Callback: r.Callback, IdempotencyKey: r.IdempotencyKey, Primary: r.Primary, Caller: r.Caller.Clone(), Network: r.Network, CurrentAddressProofPolicy: email.NotifyCurrentAddress}
	change.Primary.Proof.Action = "identity.email.change-request"
	change.Caller.Request.Action = "identity.email.change-request"
	if err := change.Validate(); err != nil {
		t.Fatal("selected change profile", err)
	}
	change.CurrentAddressProofPolicy = 0
	if change.Validate() == nil {
		t.Fatal("absent old-address policy inferred")
	}
	for _, value := range []any{r, r.Primary, change} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("request implicitly serialized")
		}
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if out := fmt.Sprintf(verb, value); !strings.Contains(out, "redacted") || strings.Contains(out, "example.test") {
				t.Fatal("request diagnostics leaked input")
			}
		}
	}
}

func TestEmailChangeRequestAcceptsOnlyExactTOTPProjection(t *testing.T) {
	r := managedSendRequest(t)
	r.Primary.Proof.Action = "identity.email.change-request"
	r.Primary.Proof.Proof.Purpose = "identity.email.change-request"
	r.Primary.Proof.Proof.Method = "totp"
	r.Primary.Proof.Proof.Assurance = auth.AssuranceMultiFactor
	r.Caller.Request.Action = "identity.email.change-request"
	change := email.ChangeRequestRequest{TenantID: r.TenantID, NewAddress: r.Address, Callback: r.Callback, IdempotencyKey: r.IdempotencyKey, Primary: r.Primary, Caller: r.Caller.Clone(), Network: r.Network, CurrentAddressProofPolicy: email.NotifyCurrentAddress}
	if err := change.Validate(); err != nil {
		t.Fatal("exact action-bound TOTP projection rejected before native admission", err)
	}
	for name, mutate := range map[string]func(*auth.ReauthenticationProof){
		"single-factor":    func(p *auth.ReauthenticationProof) { p.Proof.Assurance = auth.AssuranceSingleFactor },
		"password-purpose": func(p *auth.ReauthenticationProof) { p.Proof.Purpose = "identity.password.verify" },
		"other-action":     func(p *auth.ReauthenticationProof) { p.Action = "identity.mfa.disable" },
		"password-method":  func(p *auth.ReauthenticationProof) { p.Proof.Method = "password" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := change
			mutate(&bad.Primary.Proof)
			if bad.Validate() == nil {
				t.Fatal("mixed factor profile admitted")
			}
		})
	}
	r.Primary.Proof.Action = "identity.email.verification-send"
	r.Caller.Request.Action = "identity.email.verification-send"
	if r.Validate() == nil {
		t.Fatal("email change factor widened verification-send")
	}
}
