package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

func phoneResetProfileFixture(t *testing.T) (password.ResetProfileConfig, password.ResetGrantSpec) {
	t.Helper()
	c, original := resetProfileFixture(t)
	original.RecoveryPath = auth.RecoveryPathPhone
	original.FactorVersion = 4
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	original.Phone = password.PhoneResetBinding{
		PreAuthTransaction: "original-phone-preauth", OTPChallengeID: "original-phone-challenge",
		AttemptID: attempt, NumberDigest: [32]byte{1}, NumberKeyVersion: 2,
		VerificationVersion: 3, FactorID: "independent-totp", FactorVersion: 5,
		RiskPolicyVersion: 6,
	}
	return c, original
}

func TestPhoneResetCapabilityScopeCannotDowngradeToEmailedReset(t *testing.T) {
	c, original := phoneResetProfileFixture(t)
	p, err := password.NewPhoneResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := p.Payload(original)
	if err != nil || payload.Operation != "identity.phone.password-reset-complete" || payload.Caveats["password.recovery-path"] != "phone_password_reset" || payload.MaxUses != 1 {
		t.Fatal("phone scope not distinct and one-use", err)
	}
	now := original.IssuedAt.Add(time.Second)
	grant := signResetGrant(t, payload, now)
	if err := p.Authorize(grant, original, now); err != nil {
		t.Fatal("verified original phone scope denied", err)
	}
	resolved, err := p.ResolveOriginal(grant, now)
	if err != nil || resolved != original {
		t.Fatal("phone scope did not round-trip unchanged", err)
	}
	emailed, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emailed.ResolveOriginal(grant, now); !errors.Is(err, password.ErrInvalidReset) {
		t.Fatal("ordinary email reset accepted phone scope without required factors")
	}
	emailOriginal := original
	emailOriginal.RecoveryPath, emailOriginal.Phone = auth.RecoveryPathEmail, password.PhoneResetBinding{}
	emailPayload, err := emailed.Payload(emailOriginal)
	if err != nil {
		t.Fatal(err)
	}
	emailGrant := signResetGrant(t, emailPayload, now)
	if _, err := p.ResolveOriginal(emailGrant, now); !errors.Is(err, password.ErrInvalidReset) {
		t.Fatal("phone profile accepted weaker emailed scope")
	}
	if _, err := emailed.Payload(original); !errors.Is(err, password.ErrInvalidReset) {
		t.Fatal("legacy profile silently enabled phone issuance")
	}
}

func TestPhoneResetCapabilityPreservesEveryOriginalDependency(t *testing.T) {
	c, original := phoneResetProfileFixture(t)
	p, err := password.NewPhoneResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := p.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	now := original.IssuedAt.Add(time.Second)
	grant := signResetGrant(t, payload, now)
	for name, change := range map[string]func(*password.ResetGrantSpec){
		"preauth":          func(s *password.ResetGrantSpec) { s.Phone.PreAuthTransaction += "x" },
		"challenge":        func(s *password.ResetGrantSpec) { s.Phone.OTPChallengeID += "x" },
		"attempt":          func(s *password.ResetGrantSpec) { s.Phone.AttemptID = s.OriginCommandID },
		"number":           func(s *password.ResetGrantSpec) { s.Phone.NumberDigest[0]++ },
		"number-key":       func(s *password.ResetGrantSpec) { s.Phone.NumberKeyVersion++ },
		"verification":     func(s *password.ResetGrantSpec) { s.Phone.VerificationVersion++ },
		"factor":           func(s *password.ResetGrantSpec) { s.Phone.FactorID += "x" },
		"factor-version":   func(s *password.ResetGrantSpec) { s.Phone.FactorVersion++ },
		"factor-authority": func(s *password.ResetGrantSpec) { s.FactorVersion++ },
		"risk-policy":      func(s *password.ResetGrantSpec) { s.Phone.RiskPolicyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			change(&changed)
			if !errors.Is(p.Authorize(grant, changed, now), password.ErrInvalidReset) {
				t.Fatal("phone recovery dependency substituted")
			}
		})
	}
}

func TestPhoneResetCapabilityRejectsMissingOrMalformedDependencies(t *testing.T) {
	c, original := phoneResetProfileFixture(t)
	p, err := password.NewPhoneResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*password.ResetGrantSpec){
		"zero-binding":          func(s *password.ResetGrantSpec) { s.Phone = password.PhoneResetBinding{} },
		"short-preauth":         func(s *password.ResetGrantSpec) { s.Phone.PreAuthTransaction = "short" },
		"large-preauth":         func(s *password.ResetGrantSpec) { s.Phone.PreAuthTransaction = strings.Repeat("x", 129) },
		"short-challenge":       func(s *password.ResetGrantSpec) { s.Phone.OTPChallengeID = "short" },
		"invalid-attempt":       func(s *password.ResetGrantSpec) { s.Phone.AttemptID = "arbitrary" },
		"zero-number":           func(s *password.ResetGrantSpec) { s.Phone.NumberDigest = [32]byte{} },
		"zero-key-version":      func(s *password.ResetGrantSpec) { s.Phone.NumberKeyVersion = 0 },
		"zero-verification":     func(s *password.ResetGrantSpec) { s.Phone.VerificationVersion = 0 },
		"missing-factor":        func(s *password.ResetGrantSpec) { s.Phone.FactorID = "" },
		"zero-factor":           func(s *password.ResetGrantSpec) { s.Phone.FactorVersion = 0 },
		"zero-factor-authority": func(s *password.ResetGrantSpec) { s.FactorVersion = 0 },
		"zero-risk-policy":      func(s *password.ResetGrantSpec) { s.Phone.RiskPolicyVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			change(&changed)
			if _, err := p.Payload(changed); !errors.Is(err, password.ErrInvalidReset) {
				t.Fatal("incomplete phone recovery scope admitted")
			}
		})
	}
	now := original.IssuedAt.Add(time.Second)
	for name, change := range map[string]func(map[string]string){
		"missing-challenge":           func(m map[string]string) { delete(m, "phone.challenge") },
		"wrong-factor-kind":           func(m map[string]string) { m["phone.factor"] = "recovery_code:5:independent-totp" },
		"noncanonical-number-version": func(m map[string]string) { m["phone.number"] = "0" + m["phone.number"] },
		"noncanonical-factor-version": func(m map[string]string) { m["phone.factor"] = "totp:05:independent-totp" },
		"noncanonical-policy-version": func(m map[string]string) { m["phone.policy"] = "03:6" },
		"overflow-policy-version":     func(m map[string]string) { m["phone.policy"] = "3:18446744073709551616" },
		"invalid-digest":              func(m map[string]string) { m["phone.number"] = "2:" + strings.Repeat("g", 64) },
		"downgraded-path":             func(m map[string]string) { m["password.recovery-path"] = "emailed_password_reset" },
		"extra-caveat":                func(m map[string]string) { m["unknown"] = "value" },
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := p.Payload(original)
			if err != nil {
				t.Fatal(err)
			}
			change(payload.Caveats)
			grant := signResetGrant(t, payload, now)
			if _, err := p.ResolveOriginal(grant, now); !errors.Is(err, password.ErrInvalidReset) {
				t.Fatal("signed but invalid phone recovery scope admitted")
			}
		})
	}
}

func TestPhoneResetBindingPreservesOpaqueIDsAndRedactsDiagnostics(t *testing.T) {
	c, original := phoneResetProfileFixture(t)
	original.Phone.FactorID = "factor:with:opaque:colons"
	p, err := password.NewPhoneResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := p.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	now := original.IssuedAt.Add(time.Second)
	resolved, err := p.ResolveOriginal(signResetGrant(t, payload, now), now)
	if err != nil || resolved != original {
		t.Fatal("opaque original factor ID truncated or reinterpreted", err)
	}
	for _, wire := range []string{fmt.Sprintf("%v", original.Phone), fmt.Sprintf("%+v", original.Phone), fmt.Sprintf("%#v", original.Phone)} {
		if strings.Contains(wire, original.Phone.FactorID) || strings.Contains(wire, original.Phone.OTPChallengeID) {
			t.Fatal("phone recovery metadata leaked")
		}
	}
	if _, err := json.Marshal(original.Phone); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("phone recovery metadata serialized")
	}
}
