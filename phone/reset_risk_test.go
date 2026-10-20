package phone_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

func initiationRiskSpec(t *testing.T) phone.PasswordResetInitiationRiskRequestSpec {
	t.Helper()
	r := resetRequestSpec(t)
	return phone.PasswordResetInitiationRiskRequestSpec{TenantID: r.TenantID, CommandID: r.CommandID, IssuanceCommandID: r.RiskIssuanceCommandID, Number: r.Number, Flow: r.Flow, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
}

func TestPhoneResetInitiationRiskInputNeedsNoInventedEvidenceOrUser(t *testing.T) {
	spec := initiationRiskSpec(t)
	r, err := phone.NewPasswordResetInitiationRiskRequest(spec)
	if err != nil {
		t.Fatal("original browser/number must suffice for owned risk lookup", err)
	}
	spec.Caller.Request.Action = "identity.phone.signin"
	got, err := r.Bindings()
	if err != nil || got.Caller.Request.Action != "identity.phone.password-reset-request" {
		t.Fatal("risk input did not freeze trusted caller", err)
	}
	if _, err = json.Marshal(r); err == nil {
		t.Fatal("risk input serialized")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, struct{ private any }{r}), "public-phone") {
			t.Fatal("nested risk input disclosed caller")
		}
	}
	if _, err := (phone.PasswordResetInitiationRiskRequest{}).Bindings(); err == nil {
		t.Fatal("zero risk input projected")
	}
	for name, mutate := range map[string]func(*phone.PasswordResetInitiationRiskRequestSpec){
		"user override":    func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.Caller.Request.Resource.ID = "selected-user" },
		"missing issuance": func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.IssuanceCommandID = "" },
		"same attempt":     func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.IssuanceCommandID = s.CommandID },
		"tenant":           func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.TenantID = "foreign" },
		"missing phone":    func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.Number = phone.Number{} },
		"wrong phase": func(s *phone.PasswordResetInitiationRiskRequestSpec) {
			s.Caller.Request.Action = "identity.phone.password-reset-complete"
		},
		"origin":  func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.Origin = "http://identity.test" },
		"network": func(s *phone.PasswordResetInitiationRiskRequestSpec) { s.Network = "2001:0db8::1" },
	} {
		t.Run(name, func(t *testing.T) {
			s := initiationRiskSpec(t)
			mutate(&s)
			if _, err := phone.NewPasswordResetInitiationRiskRequest(s); err == nil {
				t.Fatal("foreign or malformed risk source admitted")
			}
		})
	}
}
