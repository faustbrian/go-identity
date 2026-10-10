package email_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

func confirmationRequest(t *testing.T) email.VerificationConfirmRequest {
	t.Helper()
	c, spec := registrationVerificationFixture(t)
	policy, err := email.NewRegistrationVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := policy.Payload(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = "confirmation-grant"
	signer, err := capability.NewHMACSHA256Signer("signing", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(token, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return email.VerificationConfirmRequest{TenantID: "tenant", CommandID: id, Token: proof, Callback: spec.Payload.Redirect, Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "confirmation-service"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user"}}}}
}

func TestVerificationConfirmRequestPreservesBorrowedCustody(t *testing.T) {
	r := confirmationRequest(t)
	for i := 0; i < 3; i++ {
		if err := r.Validate(); err != nil {
			t.Fatal("valid request", err)
		}
	}
	if err := r.Token.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Validate(), email.ErrInvalidVerification) {
		t.Fatal("transferred proof admitted")
	}
}

func TestVerificationConfirmRequestRejectsInvalidProvenance(t *testing.T) {
	for name, change := range map[string]func(*email.VerificationConfirmRequest){
		"tenant":             func(r *email.VerificationConfirmRequest) { r.TenantID = "other" },
		"command":            func(r *email.VerificationConfirmRequest) { r.CommandID = "" },
		"proof":              func(r *email.VerificationConfirmRequest) { r.Token = capability.Proof{} },
		"callback":           func(r *email.VerificationConfirmRequest) { r.Callback.Scheme = "http" },
		"invalid port":       func(r *email.VerificationConfirmRequest) { r.Callback.Host = "app.example.test:bad" },
		"broken brackets":    func(r *email.VerificationConfirmRequest) { r.Callback.Host = "[::1" },
		"invalid IP literal": func(r *email.VerificationConfirmRequest) { r.Callback.Host = "[not-an-ip]" },
		"ignored raw path":   func(r *email.VerificationConfirmRequest) { r.Callback.RawPath = strings.Repeat("x", 2049) },
		"callback total":     func(r *email.VerificationConfirmRequest) { r.Callback.RawQuery = strings.Repeat("x", 2048) },
		"network":            func(r *email.VerificationConfirmRequest) { r.Network = "client override" },
		"zoned network":      func(r *email.VerificationConfirmRequest) { r.Network = "fe80::1%en0" },
		"action":             func(r *email.VerificationConfirmRequest) { r.Caller.Request.Action = "identity.password.reset" },
		"resource":           func(r *email.VerificationConfirmRequest) { r.Caller.Request.Resource.Type = "identity.session" },
		"policy":             func(r *email.VerificationConfirmRequest) { r.Caller.PolicyRevision = 0 },
		"groups": func(r *email.VerificationConfirmRequest) {
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := confirmationRequest(t)
			change(&r)
			if !errors.Is(r.Validate(), email.ErrInvalidVerification) {
				t.Fatal("invalid request admitted")
			}
		})
	}
}

func TestVerificationConfirmRequestDiagnostics(t *testing.T) {
	r := confirmationRequest(t)
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, []email.VerificationConfirmRequest{r}), "confirmation-service") || strings.Contains(fmt.Sprintf(verb, r), "app.example.test") {
			t.Fatal("sensitive request disclosed")
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, email.ErrSensitiveSerialization) {
		t.Fatal("request serialized", err)
	}
	if _, err := r.MarshalText(); !errors.Is(err, email.ErrSensitiveSerialization) {
		t.Fatal("request serialized to text", err)
	}
}

func TestVerificationConfirmRequestBoundsBeforeWork(t *testing.T) {
	r := confirmationRequest(t)
	for _, size := range []int{2048, 2049} {
		bounded := r
		bounded.Callback.RawQuery = ""
		bounded.Callback.Path = "/" + strings.Repeat("x", size-len("https://"+bounded.Callback.Host+"/"))
		if len(bounded.Callback.String()) != size || (bounded.Validate() == nil) != (size == 2048) {
			t.Fatal("callback total byte boundary")
		}
	}
	r.Caller.Request.Attributes = authorization.Attributes{"claim": authorization.StringValue(strings.Repeat("x", 4097))}
	if r.Validate() == nil {
		t.Fatal("oversized attribute admitted")
	}
	r.Caller.Request.Attributes = authorization.Attributes{"claim": authorization.StringValue(strings.Repeat("x", 4096))}
	if err := r.Validate(); err != nil {
		t.Fatal("inclusive attribute denied", err)
	}
	r.Caller.Request.Environment.Time = time.Unix(1791637200, 0).In(time.FixedZone("caller-selected", 0))
	if r.Validate() == nil {
		t.Fatal("retained timezone admitted")
	}

	r = confirmationRequest(t)
	signer, err := capability.NewHMACSHA256Signer("signing", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"email"}, Subject: "user", Resource: "address", Operation: "identity.identifier.verify", ID: "oversized", IssuedAt: time.Unix(1791637200, 0).UTC(), NotBefore: time.Unix(1791637200, 0).UTC(), ExpiresAt: time.Unix(1791637500, 0).UTC(), MaxUses: 1, Caveats: map[string]string{}}
	for i := 0; i < 10; i++ {
		payload.Caveats[string(rune('a'+i))] = strings.Repeat("x", 400)
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil || len(token) <= 4096 {
		t.Fatal("canonical oversized fixture", err)
	}
	r.Token, err = capability.ParseProof(token, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Validate(), email.ErrInvalidVerification) {
		t.Fatal("oversized opaque proof admitted")
	}
	if err := r.Token.Transfer(context.Background(), func(_ context.Context, b []byte) error {
		if string(b) != token {
			t.Error("rejected request changed custody")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationConfirmRequestSharedPolicyAuthorities(t *testing.T) {
	for _, issuer := range []bool{true, false} {
		c, _ := registrationVerificationFixture(t)
		if issuer {
			c.Issuer = "https://[not-an-ip]"
		} else {
			c.Redirects = []string{"https://[not-an-ip]/verified"}
		}
		if _, err := email.NewRegistrationVerificationPolicy(c); !errors.Is(err, email.ErrInvalidVerification) {
			t.Fatal("invalid literal authority admitted by shared policy", err)
		}
	}
	for _, host := range []string{"[::1]", "[2001:db8::1]:443", "app.example.test:8443"} {
		r := confirmationRequest(t)
		r.Callback.Host = host
		if err := r.Validate(); err != nil {
			t.Fatal("valid HTTPS authority denied", err)
		}
	}
}
