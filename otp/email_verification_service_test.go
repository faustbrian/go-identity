package otp_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestEmailVerificationRequestsPreserveSelfSessionScopeAndSecretCustody(t *testing.T) {
	flow, _ := otp.NewSessionSendFlow("original-session", auth.NewBearerCredential(strings.Repeat("A", 43)))
	key, _ := identity.NewIdempotencyKey([]byte("original-email-request"))
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}
	r := otp.EmailVerificationSendRequest{TenantID: "tenant", UserID: "user", AddressID: "pending", AddressVersion: 1, Caller: caller, Flow: flow, Network: "127.0.0.1", Device: "original-device", IdempotencyKey: key}
	if err := r.Validate(); err != nil {
		t.Fatal("valid native email request rejected", err)
	}
	for name, change := range map[string]func(*otp.EmailVerificationSendRequest){
		"missing-key":      func(r *otp.EmailVerificationSendRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing-version":  func(r *otp.EmailVerificationSendRequest) { r.AddressVersion = 0 },
		"overflow-version": func(r *otp.EmailVerificationSendRequest) { r.AddressVersion = ^uint64(0) },
		"missing-address":  func(r *otp.EmailVerificationSendRequest) { r.AddressID = "" },
		"foreign-tenant":   func(r *otp.EmailVerificationSendRequest) { r.TenantID = "other" },
		"foreign-user":     func(r *otp.EmailVerificationSendRequest) { r.UserID = "other" },
		"missing-session":  func(r *otp.EmailVerificationSendRequest) { r.Flow = otp.SendFlow{} },
		"preauth": func(r *otp.EmailVerificationSendRequest) {
			r.Flow, _ = otp.NewPreAuthSendFlow("AQEBAQEBAQEBAQEBAQEBAQ", auth.NewBearerCredential(strings.Repeat("A", 43)))
		},
		"service-actor": func(r *otp.EmailVerificationSendRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
		"other-action": func(r *otp.EmailVerificationSendRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Action = "identity.otp.signin"
		},
		"invalid-network": func(r *otp.EmailVerificationSendRequest) { r.Network = "localhost" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("unsupported email OTP input admitted")
			}
		})
	}
	send, _ := identity.NewCommandID()
	command, _ := identity.NewCommandID()
	b := otp.CheckRecoveryBindings{SendCommandID: send, Attempt: otp.AttemptRecoveryIdentity{CommandID: command, TenantID: "tenant", AttemptID: "AQEBAQEBAQEBAQEBAQEBAQ", Fingerprint: otp.AttemptFingerprint(base64.RawURLEncoding.EncodeToString(bytesOf(32, 2))), FingerprintKeyVersion: 1}, ExpectedVersion: 2, DigestKeyVersion: 3, ScopeDigest: [32]byte{4}}
	recovery, err := otp.NewEmailVerifyRecovery(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := recovery.Bindings()
	if err != nil || got != b {
		t.Fatal("original recovery changed")
	}
	b.SendCommandID = command
	if _, err := otp.NewEmailVerifyRecovery(b); err == nil {
		t.Fatal("send and consuming command alias accepted")
	}
	code, _ := auth.NewOneTimeCode("123456")
	verifyCaller := caller.Clone()
	verifyCaller.Request.Action = "identity.otp.email-verify"
	verify := otp.EmailVerifyRequest{TenantID: "tenant", UserID: "user", Caller: verifyCaller, Flow: flow, SendCommandID: send, Code: code}
	if err := verify.Validate(); err != nil {
		t.Fatal(err)
	}
	recoverCaller := caller.Clone()
	recoverCaller.Request.Action = "identity.otp.email-verify.recover"
	history := otp.EmailVerifyRecoveryRequest{TenantID: "tenant", UserID: "user", Caller: recoverCaller, Flow: flow, Recovery: recovery}
	if err := history.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{r, verify, recovery, history, otp.EmailVerifyResult{CommandID: command, Recovery: recovery}, otp.EmailVerificationChallenge{UserID: "user"}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private email OTP custody implicitly exported")
		}
		text := fmt.Sprintf("%#v", value)
		for _, secret := range []string{"123456", strings.Repeat("A", 43), string(send), string(command), "original-session", "original-device"} {
			if strings.Contains(text, secret) {
				t.Fatal("private email OTP custody entered diagnostic")
			}
		}
	}
	if (otp.EmailVerifyRequest{}).Validate() == nil || (otp.EmailVerifyRecoveryRequest{}).Validate() == nil {
		t.Fatal("zero completion or recovery admitted")
	}
}
