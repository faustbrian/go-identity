package otp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestEmailChangeTargetCommitsOriginalIntentWithoutNarrowingIdentifierBounds(t *testing.T) {
	spec := otp.EmailChangeTargetSpec{OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", OriginOutputDigest: [32]byte{1}, IdentifierID: identity.IdentifierID(strings.Repeat("x", 128)), IdentifierVersion: 2, VerificationVersion: 2, FactorVersion: 7}
	target, err := otp.NewEmailChangeTarget(spec)
	if err != nil {
		t.Fatal("maximum supported identifier rejected", err)
	}
	raw, err := target.ScopeTarget()
	if err != nil || len(raw) > 256 || !strings.HasPrefix(raw, "email_change_otp:v1:") || strings.Contains(raw, string(spec.IdentifierID)) {
		t.Fatal("change scope lost bounded original-intent commitment", err)
	}
	command, err := otp.EmailChangeOriginCommand(raw)
	if err != nil || command != spec.OriginCommandID {
		t.Fatal("native workflow cannot locate original committed change without a second store", err)
	}
	got, err := target.Bindings()
	if err != nil || got != spec {
		t.Fatal("original change binding changed", err)
	}
	rebuilt, err := otp.NewEmailChangeTarget(got)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := rebuilt.ScopeTarget()
	if again != raw {
		t.Fatal("identical original input changed target")
	}
	for name, change := range map[string]func(*otp.EmailChangeTargetSpec){
		"origin":                         func(s *otp.EmailChangeTargetSpec) { s.OriginCommandID = "AgICAgICAgICAgICAgICAg" },
		"original old address or policy": func(s *otp.EmailChangeTargetSpec) { s.OriginOutputDigest[1] = 2 },
		"candidate":                      func(s *otp.EmailChangeTargetSpec) { s.IdentifierID = "another-candidate" },
		"candidate generation":           func(s *otp.EmailChangeTargetSpec) { s.IdentifierVersion++; s.VerificationVersion++ },
		"factor generation":              func(s *otp.EmailChangeTargetSpec) { s.FactorVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := spec
			change(&changed)
			other, err := otp.NewEmailChangeTarget(changed)
			if err != nil {
				t.Fatal(err)
			}
			otherScope, _ := other.ScopeTarget()
			if otherScope == raw {
				t.Fatal("changed original change intent retained OTP authority binding")
			}
		})
	}
	for _, invalid := range []otp.EmailChangeTargetSpec{{}, {OriginCommandID: spec.OriginCommandID, IdentifierID: "candidate", IdentifierVersion: 1, VerificationVersion: 1, FactorVersion: 1}} {
		if _, err := otp.NewEmailChangeTarget(invalid); err == nil {
			t.Fatal("absent authenticated original intent admitted")
		}
	}
	for _, value := range []any{spec, target} {
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("private change target disclosed by diagnostics")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private change intent implicitly serialized")
		}
	}
	if _, err := (otp.EmailChangeTarget{}).ScopeTarget(); err == nil {
		t.Fatal("zero target exposed usable scope")
	}
}

func TestEmailChangeOriginLocatorRejectsMalformedScope(t *testing.T) {
	spec := otp.EmailChangeTargetSpec{OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", OriginOutputDigest: [32]byte{1}, IdentifierID: "candidate", IdentifierVersion: 1, VerificationVersion: 1, FactorVersion: 1}
	target, _ := otp.NewEmailChangeTarget(spec)
	raw, _ := target.ScopeTarget()
	for _, value := range []string{"", strings.Repeat("x", 257), strings.Replace(raw, ":v1:", ":v2:", 1), raw + "=", raw + ":extra", strings.Replace(raw, string(spec.OriginCommandID), "not-a-command", 1), otp.EmailChangeRecoveryPath + ":v1:" + string(spec.OriginCommandID) + ":"} {
		if command, err := otp.EmailChangeOriginCommand(value); err == nil || command != "" {
			t.Fatal("malformed change scope returned an original locator")
		}
	}
}

func TestEmailChangeTargetRejectsInvalidOriginalBoundaries(t *testing.T) {
	base := otp.EmailChangeTargetSpec{OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", OriginOutputDigest: [32]byte{1}, IdentifierID: "candidate", IdentifierVersion: 1, VerificationVersion: 1, FactorVersion: 1}
	for name, mutate := range map[string]func(*otp.EmailChangeTargetSpec){
		"empty command":              func(s *otp.EmailChangeTargetSpec) { s.OriginCommandID = "" },
		"noncanonical command":       func(s *otp.EmailChangeTargetSpec) { s.OriginCommandID = "AQEBAQEBAQEBAQEBAQEBAQ==" },
		"absent digest":              func(s *otp.EmailChangeTargetSpec) { s.OriginOutputDigest = [32]byte{} },
		"absent candidate":           func(s *otp.EmailChangeTargetSpec) { s.IdentifierID = "" },
		"oversized candidate":        func(s *otp.EmailChangeTargetSpec) { s.IdentifierID = identity.IdentifierID(strings.Repeat("x", 129)) },
		"unsafe candidate":           func(s *otp.EmailChangeTargetSpec) { s.IdentifierID = "candidate\x00suffix" },
		"zero identifier generation": func(s *otp.EmailChangeTargetSpec) { s.IdentifierVersion = 0; s.VerificationVersion = 0 },
		"terminal identifier generation": func(s *otp.EmailChangeTargetSpec) {
			s.IdentifierVersion = ^uint64(0)
			s.VerificationVersion = ^uint64(0)
		},
		"different verification generation": func(s *otp.EmailChangeTargetSpec) { s.VerificationVersion++ },
		"zero factor":                       func(s *otp.EmailChangeTargetSpec) { s.FactorVersion = 0 },
		"terminal factor":                   func(s *otp.EmailChangeTargetSpec) { s.FactorVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			mutate(&s)
			out, err := otp.NewEmailChangeTarget(s)
			if err == nil || out != (otp.EmailChangeTarget{}) {
				t.Fatal("invalid original target admitted")
			}
		})
	}
	if _, err := (otp.EmailChangeTarget{}).Bindings(); err == nil {
		t.Fatal("zero target returned original bindings")
	}
}

func FuzzEmailChangeTarget(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "candidate", uint64(1), uint64(1), uint64(7), []byte{1})
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", strings.Repeat("x", 128), uint64(2), uint64(2), uint64(7), []byte{1, 2})
	f.Add("", "", uint64(0), uint64(0), ^uint64(0), []byte{})
	f.Fuzz(func(t *testing.T, command, candidate string, identifier, verification, factor uint64, digest []byte) {
		var original [32]byte
		copy(original[:], digest)
		s := otp.EmailChangeTargetSpec{OriginCommandID: identity.CommandID(command), OriginOutputDigest: original, IdentifierID: identity.IdentifierID(candidate), IdentifierVersion: identifier, VerificationVersion: verification, FactorVersion: factor}
		target, err := otp.NewEmailChangeTarget(s)
		if err != nil {
			if target != (otp.EmailChangeTarget{}) {
				t.Fatal("invalid input returned partial target")
			}
			return
		}
		bound, err := target.Bindings()
		if err != nil || bound != s {
			t.Fatal("valid original input changed")
		}
		scope, err := target.ScopeTarget()
		if err != nil || len(scope) > 256 || !strings.HasPrefix(scope, otp.EmailChangeRecoveryPath+":v1:") {
			t.Fatal("unbounded or unversioned target")
		}
		origin, err := otp.EmailChangeOriginCommand(scope)
		if err != nil || origin != s.OriginCommandID {
			t.Fatal("bounded locator lost original change")
		}
		rebuilt, err := otp.NewEmailChangeTarget(bound)
		if err != nil {
			t.Fatal("original target cannot be reconstructed")
		}
		again, _ := rebuilt.ScopeTarget()
		if again != scope {
			t.Fatal("original target is nondeterministic")
		}
	})
}

func FuzzEmailChangeOriginCommand(f *testing.F) {
	target, _ := otp.NewEmailChangeTarget(otp.EmailChangeTargetSpec{OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", OriginOutputDigest: [32]byte{1}, IdentifierID: "candidate", IdentifierVersion: 1, VerificationVersion: 1, FactorVersion: 1})
	raw, _ := target.ScopeTarget()
	f.Add(raw)
	f.Add("")
	f.Add(raw + ":extra")
	f.Fuzz(func(t *testing.T, input string) {
		origin, err := otp.EmailChangeOriginCommand(input)
		if err != nil {
			if origin != "" {
				t.Fatal("invalid target returned partial locator")
			}
			return
		}
		if _, err := identity.ParseCommandID(string(origin)); err != nil || !strings.HasPrefix(input, otp.EmailChangeRecoveryPath+":v1:"+string(origin)+":") || len(input) > 256 {
			t.Fatal("accepted locator is noncanonical or unbounded")
		}
	})
}
