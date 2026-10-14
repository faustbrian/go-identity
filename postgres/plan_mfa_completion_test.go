package postgres

import (
	"bytes"
	"crypto/sha256"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func mfaCompletionPlanFixture(t *testing.T, method string) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := magicLinkConsumptionPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.mfa."+method, "mfa-"+method
	p.Feature.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	p.Feature.Contributor = ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
	p.Contributors[3] = p.Feature.Contributor
	p.Capability.Purpose = "identity.mfa.complete"
	p.Capability.CapabilityID = "AgICAgICAgICAgICAgICAg"
	p.MFACompletion = &MFACompletionPlan{ID: identity.CommandID(p.Capability.CapabilityID), UserID: "factor-user", ScopeDigest: [32]byte{7}, PolicyVersion: 2, FactorVersion: 3, ContinuationVersion: 1}
	if method == "otp-verify" {
		_, otp := otpPlanFixture(t)
		p.OTP = otp.OTP
		p.Contributors = append(p.Contributors[:len(p.Contributors)-1:len(p.Contributors)-1], otpDescriptor(), p.Contributors[len(p.Contributors)-1])
	}
	return b, p
}

func TestMFACompletionPlanRoundTripRetainsNamedFactorOperation(t *testing.T) {
	for _, method := range []string{"totp-verify", "otp-verify", "recovery-use", "security-key-assert-verify"} {
		t.Run(method, func(t *testing.T) {
			b, p := mfaCompletionPlanFixture(t, method)
			fp := [32]byte{1}
			wire, err := encodeFeaturePlan(b, fp, p)
			if err != nil {
				t.Fatal("named factor cannot consume MFA continuation", err)
			}
			got, err := decodeFeaturePlan(b, fp, wire)
			if err != nil || got.MFACompletion == nil || *got.MFACompletion != *p.MFACompletion || got.Feature.Operation.OperationID != b.OperationID || got.Capability.Purpose != "identity.mfa.complete" || got.Digest != sha256.Sum256(wire) {
				t.Fatal("lost factor/continuation scope", err)
			}
			again, err := encodeFeaturePlan(b, fp, got)
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatal("changed completion history", err)
			}
			for i := range wire {
				if _, err := decodeFeaturePlan(b, fp, wire[:i]); err == nil {
					t.Fatal("truncated completion admitted", i)
				}
			}
			if _, err := KernelPlanDigest(b, fp, p); err == nil {
				t.Fatal("completion escaped typed feature profile")
			}
		})
	}
}

func TestMFACompletionOTPRequiresConsumingOwnerAndRetainsAttempt(t *testing.T) {
	b, p := mfaCompletionPlanFixture(t, "otp-verify")
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.OTP == nil || *got.OTP != *p.OTP {
		t.Fatal("OTP consumption omitted", err)
	}
	if !preparationFinalDeclaration(b, p, p) {
		t.Fatal("OTP MFA preparation rejected")
	}
	for _, mode := range []string{"missing attempt", "nonconsuming attempt", "missing owner", "changed submission"} {
		bad := p
		bad.OTP = cloneOTPPlan(p.OTP)
		bad.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
		switch mode {
		case "missing attempt":
			bad.OTP = nil
		case "nonconsuming attempt":
			bad.OTP.Mode = OTPCheck
		case "missing owner":
			bad.Contributors = append(bad.Contributors[:len(bad.Contributors)-2], bad.Contributors[len(bad.Contributors)-1])
		case "changed submission":
			bad.OTP.AttemptFingerprint[0]++
		}
		if preparationFinalDeclaration(b, p, bad) {
			t.Fatal("restoration substituted OTP", mode)
		}
		if mode != "changed submission" {
			if _, err := encodeFeaturePlan(b, [32]byte{1}, bad); err == nil {
				t.Fatal("OTP completion lacked exact consuming participant", mode)
			}
		}
	}
}

func FuzzMFACompletionPlan(f *testing.F) {
	f.Add([]byte{0xa6})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		for _, method := range []string{"totp-verify", "otp-verify"} {
			b, p := mfaCompletionPlanFixture(t, method)
			fp := [32]byte{1}
			wire, err := encodeFeaturePlan(b, fp, p)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range [][]byte{wire, data} {
				got, err := decodeFeaturePlan(b, fp, input)
				if err != nil {
					continue
				}
				again, err := encodeFeaturePlan(b, fp, got)
				if err != nil || !bytes.Equal(input, again) {
					t.Fatal("accepted noncanonical completion")
				}
				if got.MFACompletion != nil && !validMFACompletionPlan(b, got) {
					t.Fatal("invalid completion decoded")
				}
			}
		}
	})
}

func TestMFACompletionRejectsSubstitutionAndProofFreeExecution(t *testing.T) {
	for name, mutate := range map[string]func(*CommandPlan){
		"missing continuation":      func(p *CommandPlan) { p.MFACompletion = nil },
		"missing proof":             func(p *CommandPlan) { p.Capability = nil },
		"retarget child":            func(p *CommandPlan) { p.MFACompletion.ID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"missing original scope":    func(p *CommandPlan) { p.MFACompletion.ScopeDigest = [32]byte{} },
		"missing factor generation": func(p *CommandPlan) { p.MFACompletion.FactorVersion = 0 },
		"missing policy generation": func(p *CommandPlan) { p.MFACompletion.PolicyVersion = 0 },
		"missing attempt version":   func(p *CommandPlan) { p.MFACompletion.ContinuationVersion = 0 },
		"changed purpose":           func(p *CommandPlan) { p.Capability.Purpose = "identity.mfa.totp-verify" },
		"session-free lifecycle":    func(p *CommandPlan) { p.Lifecycle.EventType = "mfa.challenge.created.v1" },
		"challenge issuance":        func(p *CommandPlan) { p.MFAContinuation = &MFAContinuationPlan{} },
		"new issuer":                func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"new delivery":              func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"unprotected audit":         func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"foreign owner":             func(p *CommandPlan) { p.Feature.Contributor.Owner = "identity/magiclink/postgres" },
		"OTP on TOTP":               func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := mfaCompletionPlanFixture(t, "totp-verify")
			mutate(&p)
			if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign/incomplete completion admitted")
			}
		})
	}
	// The exception is confined to completion, not a global purpose relaxation.
	b, p := magicLinkConsumptionPlanFixture(t)
	p.Capability.Purpose = "identity.mfa.complete"
	if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
		t.Fatal("MFA purpose accepted by primary login")
	}
}
