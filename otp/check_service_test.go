package otp_test

import (
	"context"
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

func TestCheckRecoveryRetainsCodeFreeOriginalIdentity(t *testing.T) {
	send, _ := identity.NewCommandID()
	command, _ := identity.NewCommandID()
	b := otp.CheckRecoveryBindings{SendCommandID: send, Attempt: otp.AttemptRecoveryIdentity{
		CommandID: command, TenantID: "tenant", AttemptID: otp.AttemptID(base64.RawURLEncoding.EncodeToString(bytesOf(16, 1))),
		Fingerprint: otp.AttemptFingerprint(base64.RawURLEncoding.EncodeToString(bytesOf(32, 2))), FingerprintKeyVersion: 7},
		ExpectedVersion: 3, DigestKeyVersion: 9, ScopeDigest: [32]byte{4}}
	r, err := otp.NewCheckRecovery(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Bindings()
	if err != nil || got != b {
		t.Fatal("original recovery metadata changed")
	}
	if _, err := (otp.CheckRecovery{}).Bindings(); err == nil {
		t.Fatal("zero recovery accepted")
	}
	for _, invalid := range []otp.CheckRecoveryBindings{{}, {SendCommandID: send, Attempt: b.Attempt}} {
		if _, err := otp.NewCheckRecovery(invalid); err == nil {
			t.Fatal("invalid recovery accepted")
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("recovery serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), string(command)) {
		t.Fatal("recovery disclosed correlation")
	}
}

// CHECK-01: introducing optional checks must not change existing Send contracts.
type sendOnlyService struct{}

func (sendOnlyService) Send(context.Context, otp.SendRequest) (otp.SendResult, error) {
	return otp.SendResult{}, nil
}

var _ otp.Service = sendOnlyService{}

func TestPublicCheckBoundsAndSecretRedaction(t *testing.T) {
	flow, _ := otp.NewSessionSendFlow("original-session", auth.NewBearerCredential(strings.Repeat("A", 43)))
	command, _ := identity.NewCommandID()
	code, _ := auth.NewOneTimeCode("123456")
	r := otp.CheckRequest{TenantID: "tenant", UserID: "user", Flow: flow, SendCommandID: command, Code: code,
		Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.otp.check", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal("valid check rejected", err)
	}
	for _, change := range []func(*otp.CheckRequest){
		func(r *otp.CheckRequest) { r.Flow = otp.SendFlow{} },
		func(r *otp.CheckRequest) { r.SendCommandID = "invalid" },
		func(r *otp.CheckRequest) { r.TenantID = "foreign" },
		func(r *otp.CheckRequest) { r.UserID = "" },
		func(r *otp.CheckRequest) { r.Caller = r.Caller.Clone(); r.Caller.Request.Subject.Kind = "unknown" },
		func(r *otp.CheckRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
	} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid check accepted")
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("code-bearing check serialized")
	}
	if _, err := r.MarshalText(); err == nil {
		t.Fatal("code-bearing check serialized as text")
	}
	for _, text := range []string{fmt.Sprintf("%+v", r), r.LogValue().String()} {
		if strings.Contains(text, "123456") || strings.Contains(text, strings.Repeat("A", 43)) {
			t.Fatal("check disclosed code or bearer")
		}
	}
	if (otp.CheckRecoveryRequest{}).Validate() == nil {
		t.Fatal("zero recovery request accepted")
	}
}

func FuzzCheckRecoveryBoundedCanonicalIdentity(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg", "AQEBAQEBAQEBAQEBAQEBAQ", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, send, command, attempt, fingerprint string) {
		b := otp.CheckRecoveryBindings{SendCommandID: identity.CommandID(send), Attempt: otp.AttemptRecoveryIdentity{CommandID: identity.CommandID(command), TenantID: "tenant", AttemptID: otp.AttemptID(attempt), Fingerprint: otp.AttemptFingerprint(fingerprint), FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}}
		r, err := otp.NewCheckRecovery(b)
		if err != nil {
			return
		}
		got, err := r.Bindings()
		if err != nil || got != b {
			t.Fatal("canonical recovery did not round trip")
		}
	})
}

func bytesOf(n int, value byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}
