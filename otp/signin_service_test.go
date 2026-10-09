package otp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func signinRequest(t *testing.T) otp.SigninRequest {
	t.Helper()
	flow, err := otp.NewPreAuthSendFlow(preAuthID(), auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	send, _ := identity.NewCommandID()
	code, _ := auth.NewOneTimeCode("123456")
	return otp.SigninRequest{TenantID: "tenant", Flow: flow, SendCommandID: send, Code: code,
		Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "public-entry"}, Action: "identity.otp.signin", Resource: authorization.Resource{Type: "identity.preauth", ID: authorization.ResourceID(preAuthID())}}}}
}

// SIGNIN-02: structural selection must not accept a session or foreign tenant.
func TestSigninRequestRequiresOriginalPreAuthVariant(t *testing.T) {
	r := signinRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*otp.SigninRequest){
		"zero flow": func(r *otp.SigninRequest) { r.Flow = otp.SendFlow{} },
		"session flow": func(r *otp.SigninRequest) {
			var err error
			r.Flow, err = otp.NewSessionSendFlow("session", auth.NewBearerCredential(strings.Repeat("B", 42)+"A"))
			if err != nil {
				t.Fatal(err)
			}
			r.UserID = "user"
		},
		"foreign tenant": func(r *otp.SigninRequest) { r.TenantID = "foreign" },
		"invalid send":   func(r *otp.SigninRequest) { r.SendCommandID = "invalid" },
		"oversized user": func(r *otp.SigninRequest) { r.UserID = identity.UserID(strings.Repeat("u", 129)) },
		"oversized caller": func(r *otp.SigninRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if bad.Validate() == nil {
				t.Fatal("invalid signin accepted")
			}
		})
	}
	if (otp.SigninRequest{}).Validate() == nil {
		t.Fatal("zero signin accepted")
	}
}

func signinRecoveryBindings(t *testing.T) otp.SigninRecoveryBindings {
	t.Helper()
	send, _ := identity.NewCommandID()
	command, _ := identity.NewCommandID()
	return otp.SigninRecoveryBindings{SendCommandID: send, Attempt: otp.AttemptRecoveryIdentity{CommandID: command, TenantID: "tenant", AttemptID: "AQEBAQEBAQEBAQEBAQEBAQ", Fingerprint: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}}
}

// SIGNIN-06: recovery retains exact code-free identity without authorizing it.
func TestSigninRecoveryImmutableBoundedAndDistinctFromSend(t *testing.T) {
	b := signinRecoveryBindings(t)
	r, err := otp.NewSigninRecovery(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Bindings()
	if err != nil || got != b {
		t.Fatal("recovery identity changed")
	}
	got.ExpectedVersion++
	again, _ := r.Bindings()
	if again != b {
		t.Fatal("projection mutated custody")
	}
	for name, change := range map[string]func(*otp.SigninRecoveryBindings){
		"invalid send":             func(b *otp.SigninRecoveryBindings) { b.SendCommandID = "invalid" },
		"same command":             func(b *otp.SigninRecoveryBindings) { b.Attempt.CommandID = b.SendCommandID },
		"zero version":             func(b *otp.SigninRecoveryBindings) { b.ExpectedVersion = 0 },
		"zero digest version":      func(b *otp.SigninRecoveryBindings) { b.DigestKeyVersion = 0 },
		"zero fingerprint version": func(b *otp.SigninRecoveryBindings) { b.Attempt.FingerprintKeyVersion = 0 },
		"zero scope":               func(b *otp.SigninRecoveryBindings) { b.ScopeDigest = [32]byte{} },
		"oversized attempt":        func(b *otp.SigninRecoveryBindings) { b.Attempt.AttemptID = otp.AttemptID(strings.Repeat("A", 10000)) },
		"noncanonical fingerprint": func(b *otp.SigninRecoveryBindings) {
			b.Attempt.Fingerprint = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			change(&bad)
			if _, err := otp.NewSigninRecovery(bad); err == nil {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
	if _, err := (otp.SigninRecovery{}).Bindings(); err == nil {
		t.Fatal("zero recovery accepted")
	}
	request := signinRequest(t)
	recover := otp.SigninRecoveryRequest{TenantID: request.TenantID, Caller: request.Caller, Flow: request.Flow, Recovery: r}
	if err := recover.Validate(); err != nil {
		t.Fatal(err)
	}
	recover.TenantID = "foreign"
	if recover.Validate() == nil {
		t.Fatal("foreign recovery accepted")
	}
	if (otp.SigninRecoveryRequest{}).Validate() == nil {
		t.Fatal("zero recovery request accepted")
	}
	recover.TenantID = request.TenantID
	recover.Flow, err = otp.NewSessionSendFlow("session", auth.NewBearerCredential(strings.Repeat("B", 42)+"A"))
	if err != nil {
		t.Fatal(err)
	}
	recover.UserID = "user"
	if recover.Validate() == nil {
		t.Fatal("session recovery accepted")
	}
}

func TestSigninContractsRejectImplicitDisclosure(t *testing.T) {
	b := signinRecoveryBindings(t)
	r, _ := otp.NewSigninRecovery(b)
	request := signinRequest(t)
	token, err := session.ParseToken(strings.Repeat("B", 42) + "A")
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(strings.Repeat("C", 42) + "A")
	if err != nil {
		t.Fatal(err)
	}
	values := []interface {
		MarshalText() ([]byte, error)
		LogValue() slog.Value
	}{request, b, r, otp.SigninRecoveryRequest{Recovery: r}, otp.SigninResult{Recovery: r, Issuance: session.IssueResult{CommandID: b.Attempt.CommandID, Token: token}, CSRFToken: csrf}}
	for _, value := range values {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit JSON disclosure")
		}
		if _, err := value.MarshalText(); err == nil {
			t.Fatal("implicit text disclosure")
		}
		texts := []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), value.LogValue().String()}
		for _, text := range texts {
			for _, secret := range []string{"123456", strings.Repeat("A", 43), strings.Repeat("B", 42) + "A", strings.Repeat("C", 42) + "A", string(b.Attempt.CommandID), string(b.Attempt.Fingerprint)} {
				if strings.Contains(text, secret) {
					t.Fatal("diagnostic disclosure")
				}
			}
		}
	}
	if wire, err := token.Reveal(); err != nil || wire != strings.Repeat("B", 42)+"A" {
		t.Fatal("diagnostics consumed original bearer")
	}
	if _, err := token.Reveal(); err == nil {
		t.Fatal("bearer revealed twice")
	}
	if wire, err := csrf.Reveal(); err != nil || wire != strings.Repeat("C", 42)+"A" {
		t.Fatal("diagnostics consumed original CSRF")
	}
}

// External consumers can compose optional signin without widening Service.
func usePublicSignin(ctx context.Context, s otp.SigninService, r otp.SigninRequest, recovery otp.SigninRecoveryRequest) {
	_, _ = s.Signin(ctx, r)
	_, _ = s.RecoverSignin(ctx, recovery)
}

func FuzzSigninRecoveryCanonicalIdentity(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg", "AQEBAQEBAQEBAQEBAQEBAQ", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, send, command, attempt, fingerprint string) {
		b := otp.SigninRecoveryBindings{SendCommandID: identity.CommandID(send), Attempt: otp.AttemptRecoveryIdentity{CommandID: identity.CommandID(command), TenantID: "tenant", AttemptID: otp.AttemptID(attempt), Fingerprint: otp.AttemptFingerprint(fingerprint), FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}}
		r, err := otp.NewSigninRecovery(b)
		if err != nil {
			return
		}
		got, err := r.Bindings()
		if err != nil || got != b || send == command {
			t.Fatal("invalid recovery round trip")
		}
	})
}
