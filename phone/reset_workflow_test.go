package phone_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

// These fixtures exercise input custody only. A syntactically valid risk
// reference and locally signed grant do not establish recovery authorization.
func resetRequestSpec(t *testing.T) phone.PasswordResetRequestRequestSpec {
	t.Helper()
	base := enrollmentRequest(t)
	flow, err := otp.NewPreAuthSendFlow("AAAAAAAAAAAAAAAAAAAAAQ", base.Session)
	if err != nil {
		t.Fatal(err)
	}
	part := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	reference, err := risk.ParseRiskEvidenceRef("re1.1." + part + "." + part)
	if err != nil {
		t.Fatal(err)
	}
	caller := base.Caller.Clone()
	caller.Request.Action = "identity.phone.password-reset-request"
	caller.Request.Subject.Kind, caller.Request.Subject.ID = authorization.SubjectServiceAccount, "public-phone"
	caller.Request.Resource.ID = ""
	return phone.PasswordResetRequestRequestSpec{TenantID: base.TenantID, CommandID: "AgICAgICAgICAgICAgICAg", Number: base.Number,
		Flow: flow, RiskEvidence: reference, RiskIssuanceCommandID: "BAQEBAQEBAQEBAQEBAQEBA", IdempotencyKey: base.IdempotencyKey, Caller: caller,
		Origin: "https://identity.test", Network: base.Network, Device: base.Device}
}

func TestPhoneResetRequestRetainsOnlyOriginalSessionlessRecoveryCustody(t *testing.T) {
	spec := resetRequestSpec(t)
	request, err := phone.NewPasswordResetRequestRequest(spec)
	if err != nil {
		t.Fatal("bounded original phone recovery request rejected", err)
	}
	spec.Caller.Request.Action = "identity.phone.signin"
	got, err := request.Bindings()
	if err != nil || got.Caller.Request.Action != "identity.phone.password-reset-request" || got.Flow != spec.Flow || got.RiskEvidence != spec.RiskEvidence || got.RiskIssuanceCommandID != spec.RiskIssuanceCommandID {
		t.Fatal("phone recovery lost original caller, flow or evidence", err)
	}
	for name, mutate := range map[string]func(*phone.PasswordResetRequestRequestSpec){
		"tenant":          func(s *phone.PasswordResetRequestRequestSpec) { s.TenantID = "foreign" },
		"missing command": func(s *phone.PasswordResetRequestRequestSpec) { s.CommandID = "" },
		"other action": func(s *phone.PasswordResetRequestRequestSpec) {
			s.Caller.Request.Action = "identity.password.reset-request"
		},
		"selected user":           func(s *phone.PasswordResetRequestRequestSpec) { s.Caller.Request.Resource.ID = "user" },
		"missing phone":           func(s *phone.PasswordResetRequestRequestSpec) { s.Number = phone.Number{} },
		"missing flow":            func(s *phone.PasswordResetRequestRequestSpec) { s.Flow = otp.SendFlow{} },
		"missing evidence":        func(s *phone.PasswordResetRequestRequestSpec) { s.RiskEvidence = risk.RiskEvidenceRef{} },
		"missing original risk":   func(s *phone.PasswordResetRequestRequestSpec) { s.RiskIssuanceCommandID = "" },
		"malformed original risk": func(s *phone.PasswordResetRequestRequestSpec) { s.RiskIssuanceCommandID = "foreign" },
		"same command risk":       func(s *phone.PasswordResetRequestRequestSpec) { s.RiskIssuanceCommandID = s.CommandID },
		"missing key":             func(s *phone.PasswordResetRequestRequestSpec) { s.IdempotencyKey = identity.IdempotencyKey{} },
		"missing origin":          func(s *phone.PasswordResetRequestRequestSpec) { s.Origin = "" },
		"noncanonical network":    func(s *phone.PasswordResetRequestRequestSpec) { s.Network = "2001:0db8::1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := resetRequestSpec(t)
			mutate(&candidate)
			if _, err := phone.NewPasswordResetRequestRequest(candidate); err == nil {
				t.Fatal("weaker or foreign original recovery admitted")
			}
		})
	}
	if _, err := (phone.PasswordResetRequestRequest{}).Bindings(); err == nil {
		t.Fatal("zero recovery request projected usable custody")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		formatted := fmt.Sprintf(verb, struct{ private any }{request})
		if strings.Contains(formatted, "+12025550123") || strings.Contains(formatted, spec.RiskEvidence.Reveal()) {
			t.Fatal("nested phone recovery request disclosed custody")
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("implicit recovery input serialization admitted")
	}
}

func TestPhoneResetCompletionRetainsBothCodesAndBorrowedPassword(t *testing.T) {
	base := resetRequestSpec(t)
	signer, err := capability.NewHMACSHA256Signer("fixture", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	wire, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://identity.test", Audiences: []string{"phone-reset"},
		Tenant: "tenant", Subject: "user", Operation: "identity.phone.password-reset-complete", Resource: "identity.password/password",
		ID: "synthetic-reset", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte(" original replacement password "))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Destroy)
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	caller := base.Caller.Clone()
	caller.Request.Action = "identity.phone.password-reset-complete"
	spec := phone.PasswordResetCompleteRequestSpec{TenantID: base.TenantID, CommandID: "AwMDAwMDAwMDAwMDAwMDAw", Flow: base.Flow,
		ResetCapability: proof, PhoneCode: sms, IndependentTOTP: totp, RiskEvidence: base.RiskEvidence, RiskIssuanceCommandID: base.RiskIssuanceCommandID, NewPassword: secret,
		Caller: caller, Origin: base.Origin, Network: base.Network, Device: base.Device}
	request, err := phone.NewPasswordResetCompleteRequest(spec)
	if err != nil {
		t.Fatal("joint original completion custody rejected", err)
	}
	retained, err := request.Bindings()
	if err != nil || retained.NewPassword.Len() != secret.Len() || retained.RiskEvidence != base.RiskEvidence || retained.Flow != base.Flow || retained.RiskIssuanceCommandID != base.RiskIssuanceCommandID {
		t.Fatal("completion dropped original recovery custody", err)
	}
	// Independent factor ownership is not numerical code inequality. The
	// actual independent TOTP can legitimately equal this SMS by coincidence.
	sameDigits := spec
	sameDigits.IndependentTOTP = sms
	if _, err := phone.NewPasswordResetCompleteRequest(sameDigits); err != nil {
		t.Fatal("code equality was mistaken for factor dependence", err)
	}
	for _, mutate := range []func(*phone.PasswordResetCompleteRequestSpec){
		func(s *phone.PasswordResetCompleteRequestSpec) { s.ResetCapability = capability.Proof{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.PhoneCode = auth.OneTimeCode{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.IndependentTOTP = auth.OneTimeCode{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.RiskEvidence = risk.RiskEvidenceRef{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.RiskIssuanceCommandID = "" },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.RiskIssuanceCommandID = "foreign" },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.RiskIssuanceCommandID = s.CommandID },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.NewPassword = primitive.Secret{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.Flow = otp.SendFlow{} },
		func(s *phone.PasswordResetCompleteRequestSpec) { s.CommandID = "" },
		func(s *phone.PasswordResetCompleteRequestSpec) {
			s.Caller = s.Caller.Clone()
			s.Caller.Request.Action = "identity.password.reset-complete"
		},
	} {
		candidate := spec
		mutate(&candidate)
		if _, err := phone.NewPasswordResetCompleteRequest(candidate); err == nil {
			t.Fatal("partial or substituted recovery conjunction admitted")
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		formatted := fmt.Sprintf(verb, struct{ private any }{request})
		if strings.Contains(formatted, wire) || strings.Contains(formatted, "123456") || strings.Contains(formatted, "654321") || strings.Contains(formatted, "replacement password") {
			t.Fatal("nested completion disclosed a factor or password")
		}
	}
	secret.Destroy()
	if _, err := request.Bindings(); err == nil {
		t.Fatal("completion renewed a destroyed original password owner")
	}
}

func FuzzPhoneResetRequestBounds(f *testing.F) {
	f.Add("https://identity.test", "192.0.2.1", "browser")
	f.Add("https://identity.test/path?query#fragment", "fe80::1%en0", "device\x00")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, origin, network, device string) {
		spec := resetRequestSpec(t)
		spec.Origin, spec.Network, spec.Device = origin, network, device
		request, err := phone.NewPasswordResetRequestRequest(spec)
		if err != nil {
			if err != phone.ErrInvalidPasswordReset {
				t.Fatal("malformed recovery input exposed a non-redacted diagnostic")
			}
			return
		}
		retained, err := request.Bindings()
		if err != nil || retained.Validate() != nil || retained.Origin != origin || retained.Network != network || retained.Device != device {
			t.Fatal("accepted original recovery input changed during projection")
		}
	})
}
