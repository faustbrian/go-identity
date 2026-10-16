package otp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestEmailChangeRequestRequiresOriginalChangeAndSelfSession(t *testing.T) {
	flow, _ := otp.NewSessionSendFlow("original-session", auth.NewBearerCredential(strings.Repeat("A", 43)))
	key, _ := identity.NewIdempotencyKey([]byte("original-change-code-request"))
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.otp.email-change-request", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}
	r := otp.EmailChangeRequest{TenantID: "tenant", UserID: "user", OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", AddressID: "pending-candidate", Caller: caller, Flow: flow, Network: "127.0.0.1", Device: "original-device", IdempotencyKey: key}
	if err := r.Validate(); err != nil {
		t.Fatal("original self-session change request rejected", err)
	}
	for name, mutate := range map[string]func(*otp.EmailChangeRequest){
		"no origin":    func(r *otp.EmailChangeRequest) { r.OriginCommandID = "" },
		"no candidate": func(r *otp.EmailChangeRequest) { r.AddressID = "" },
		"no key":       func(r *otp.EmailChangeRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"foreign user": func(r *otp.EmailChangeRequest) { r.UserID = "foreign" },
		"wrong purpose": func(r *otp.EmailChangeRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Action = "identity.otp.send"
		},
		"invalid network": func(r *otp.EmailChangeRequest) { r.Network = "localhost" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid or aliased change scope admitted")
			}
		})
	}
	code, _ := auth.NewOneTimeCode("123456")
	confirmCaller := caller.Clone()
	confirmCaller.Request.Action = "identity.otp.email-change-confirm"
	confirm := otp.EmailChangeConfirmRequest{TenantID: "tenant", UserID: "user", Caller: confirmCaller, Flow: flow, SendCommandID: "AgICAgICAgICAgICAgICAg", Code: code}
	if err := confirm.Validate(); err != nil {
		t.Fatal(err)
	}
	confirm.Caller.Request.Action = "identity.otp.email-verify"
	if confirm.Validate() == nil {
		t.Fatal("verification-only caller entered primary replacement")
	}
	for _, value := range []any{r, confirm, otp.EmailChangeRecovery{}, otp.EmailChangeRecoveryRequest{}, otp.EmailChangeResult{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private change custody exported implicitly")
		}
		if output := fmt.Sprintf("%#v", value); !strings.Contains(output, "redacted") || strings.Contains(output, "123456") || strings.Contains(output, "original-session") {
			t.Fatal("private change custody disclosed in diagnostics")
		}
	}
	if _, err := (otp.EmailChangeRecovery{}).Bindings(); err == nil {
		t.Fatal("zero recovery authorized history")
	}
}
