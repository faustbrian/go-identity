package otp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestSigninSourceRetainsOriginalScopeWithoutAuthority(t *testing.T) {
	r := signinRequest(t)
	request := otp.SigninSourceRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, SendCommandID: r.SendCommandID}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if (otp.SigninSourceRequest{}).Validate() == nil {
		t.Fatal("zero source selection accepted")
	}
	bad := request
	bad.TenantID = "foreign"
	if bad.Validate() == nil {
		t.Fatal("foreign tenant admitted")
	}
	destination, _ := otp.NewDestinationInput("original@example.invalid")
	b := otp.SigninSourceBindings{TenantID: r.TenantID, SendCommandID: r.SendCommandID, Channel: otp.ChannelEmail, Destination: destination}
	s, err := otp.NewSigninSource(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Bindings()
	if err != nil || got != b {
		t.Fatal("source scope changed")
	}
	got.TenantID = "different"
	again, _ := s.Bindings()
	if again != b {
		t.Fatal("caller projection rewrote source")
	}
	for _, invalid := range []otp.SigninSourceBindings{
		{}, {TenantID: identity.TenantID(strings.Repeat("t", 129)), SendCommandID: b.SendCommandID, Channel: b.Channel, Destination: destination},
		{TenantID: b.TenantID, SendCommandID: "invalid", Channel: b.Channel, Destination: destination},
		{TenantID: b.TenantID, SendCommandID: b.SendCommandID, Channel: "unknown", Destination: destination},
		{TenantID: b.TenantID, SendCommandID: b.SendCommandID, Channel: b.Channel},
	} {
		if _, err := otp.NewSigninSource(invalid); err == nil {
			t.Fatal("invalid source scope accepted")
		}
	}
	if _, err := (otp.SigninSource{}).Bindings(); err == nil {
		t.Fatal("zero source accepted")
	}
	for _, value := range []any{request, b, s} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("source implicitly serialized")
		}
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(verb, value)
			if strings.Contains(text, destination.Value()) || strings.Contains(text, string(b.SendCommandID)) || strings.Contains(text, strings.Repeat("A", 43)) {
				t.Fatal("source diagnostics disclosed custody")
			}
		}
	}
}
