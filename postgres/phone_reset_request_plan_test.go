package postgres

import "testing"

// Declaration grammar only. The real native request must independently admit
// the original pre-auth, recipient, password, factor and signed risk evidence.
func phoneResetRequestPlanFixture(t *testing.T) (CommandPlan, CommandPlan) {
	t.Helper()
	_, _, original := riskReservationFixture(t, &riskReservationProbe{})
	original.SubjectType = "otp_challenge"
	original.Lifecycle = &LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}
	original.Audits[0].EventType = "otp.send"
	final := clonePhoneResetRequestPlan(original)
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.Grants[0].Purpose = "identity.phone.password-reset-complete"
	final.Delivery = deliveryTestPlan()
	final.Contributors = append(final.Contributors, final.CapabilityIssuance.Contributor, final.Delivery.Contributor)
	return original, final
}

func TestPhoneResetRequestPreparationKeepsRiskAndCompleteIssuance(t *testing.T) {
	original, final := phoneResetRequestPlanFixture(t)
	_, command, _ := riskReservationFixture(t, &riskReservationProbe{})
	spec, _ := command.Feature()
	if preparationProtected(original) {
		t.Fatal("original SMS request cannot retain initiation risk before generation")
	}
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, original)
	if err != nil {
		t.Fatal("exact SMS initiation declaration rejected", err)
	}
	decoded, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || decoded.RiskEvidence == nil || *decoded.RiskEvidence != *original.RiskEvidence {
		t.Fatal("original initiation risk changed in stored declaration", err)
	}
	if !preparationFinalDeclaration(spec.Binding, original, final) {
		t.Fatal("SMS and canonical reset-capability issuance cannot attach together")
	}
	completed, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, final)
	if err != nil {
		t.Fatal("complete request effects cannot enter the final plan", err)
	}
	restored, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, completed)
	if err != nil || restored.CapabilityIssuance == nil || restored.Delivery == nil || restored.RiskEvidence == nil || !preparationFinalDeclaration(spec.Binding, decoded, restored) {
		t.Fatal("stored request dropped or substituted atomic effects", err)
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"missing capability": func(p *CommandPlan) { p.CapabilityIssuance = nil },
		"missing delivery":   func(p *CommandPlan) { p.Delivery = nil },
		"email purpose":      func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete" },
		"extra grant": func(p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
		"recipient override": func(p *CommandPlan) { p.CapabilityIssuance.ResetRecipientUserID = "other" },
		"risk replacement":   func(p *CommandPlan) { p.RiskEvidence.ProofDigest[0]++ },
		"risk renewal":       func(p *CommandPlan) { p.RiskEvidence.ExpiresAt = p.RiskEvidence.ExpiresAt.Add(1) },
		"completion risk":    func(p *CommandPlan) { p.RiskEvidence.Phase = "phone-reset-completion" },
		"consuming OTP":      func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{Mode: OTPConsume} },
		"wrong event":        func(p *CommandPlan) { p.Lifecycle.EventType = "phone.reset.v1" },
		"wrong subject":      func(p *CommandPlan) { p.SubjectType = "phone" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clonePhoneResetRequestPlan(final)
			mutate(&bad)
			if preparationFinalDeclaration(spec.Binding, original, bad) {
				t.Fatal("incomplete or substituted phone request attached")
			}
		})
	}
}

func clonePhoneResetRequestPlan(p CommandPlan) CommandPlan {
	p.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
	p.Audits = append([]AuditPlan(nil), p.Audits...)
	feature, lifecycle, risk := *p.Feature, *p.Lifecycle, *p.RiskEvidence
	p.Feature, p.Lifecycle, p.RiskEvidence = &feature, &lifecycle, &risk
	p.CapabilityIssuance = cloneCapabilityIssuancePlan(p.CapabilityIssuance)
	return p
}

func TestPhoneResetRequestRetainsLegacyRiskIssuanceHistory(t *testing.T) {
	_, command, legacy := riskReservationFixture(t, &riskReservationProbe{})
	spec, _ := command.Feature()
	if !preparationProtected(legacy) {
		t.Fatal("legacy phone declaration gained a new preparation path")
	}
	legacy.CapabilityIssuance = issuanceTestPlan()
	legacy.Contributors = append(legacy.Contributors, legacy.CapabilityIssuance.Contributor)
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, legacy)
	if err != nil {
		t.Fatal("previously valid legacy issuance history became unreadable", err)
	}
	if _, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire); err != nil {
		t.Fatal("retained legacy issuance failed reconstruction", err)
	}
}
