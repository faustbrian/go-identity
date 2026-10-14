package postgres

import (
	"crypto/hmac"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// Keep submitted intent and server-prepared counter state separate only for
// the closed native anonymous TOTP/OTP/recovery profiles. Generic codecs stay exact.
// Native counter validation and the complete frozen plan still bind every
// prepared counter field; nothing permits replacing an existing declaration.
func (c *Coordinator) originalMFAClaim(original, prepared identity.Command, plan *admittedKernelPlan) (claimRequest, *admittedKernelPlan, error) {
	fail := func() (claimRequest, *admittedKernelPlan, error) { return claimRequest{}, nil, invalidPlan() }
	if c == nil || c.registry == nil || plan == nil || plan.counters == nil || plan.feature == nil || !validMFACompletionPlan(plan.binding, plan.snapshot()) {
		return fail()
	}
	base, baseOK := original.Feature()
	full, fullOK := prepared.Feature()
	cookie, cookieOK := prepared.PreAuthCookie()
	if !baseOK || !fullOK || !cookieOK || base.Binding != full.Binding || base.Operation != full.Operation || base.Binding != plan.binding || full.Operation != plan.feature.Operation {
		return fail()
	}
	for _, field := range base.Fields {
		if strings.HasPrefix(field.Name, "counter.") || full.Operation.OperationID == "identity.mfa.otp-verify" && (field.Name == "otp" || strings.HasPrefix(field.Name, "otp.")) {
			return fail()
		}
	}
	filtered := full
	filtered.Fields = nil
	count := 0
	otpFields := 0
	for _, field := range full.Fields {
		if strings.HasPrefix(field.Name, "counter.") {
			switch field.Name {
			case "counter.network", "counter.session", "counter.subject", "counter.capability", "counter.prepared-at", "counter.key-versions":
				count++
			default:
				return fail()
			}
		} else if full.Operation.OperationID == "identity.mfa.otp-verify" && (field.Name == "otp" || strings.HasPrefix(field.Name, "otp.")) {
			switch field.Name {
			case "otp.attempt-custody":
				if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) == 0 || len(field.Value.Bytes) > 8192 {
					return fail()
				}
			case "otp.digest-key-version":
				if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 == 0 || field.Value.Uint64 > uint64(^uint32(0)) {
					return fail()
				}
			default:
				return fail()
			}
			otpFields++
		} else {
			filtered.Fields = append(filtered.Fields, field)
		}
	}
	if count != 6 {
		return fail()
	}
	if full.Operation.OperationID == "identity.mfa.otp-verify" && (otpFields != 2 || plan.otp == nil || !mfaOTPNetworkMatches(base, full) || validateOTPAttempt(otpAttemptOwner(plan), prepared, *plan.otp) != nil) {
		return fail()
	}
	var stripped identity.Command
	var err error
	switch full.Operation.OperationID {
	case "identity.mfa.totp-verify", "identity.mfa.otp-verify":
		code, ok := prepared.OneTimeCode()
		if !ok {
			return fail()
		}
		stripped, err = identity.NewFeatureOneTimeCodePreAuthCommand(filtered, code, cookie)
	case "identity.mfa.recovery-use":
		code, ok := prepared.RecoveryCode()
		if !ok {
			return fail()
		}
		stripped, err = identity.NewFeatureRecoveryCodePreAuthCommand(filtered, code, cookie)
	default:
		return fail()
	}
	if err != nil {
		return fail()
	}
	key := c.keys.retained[c.keys.current]
	q, err := prepareClaim(original, key)
	if err != nil {
		return fail()
	}
	comparison, err := prepareClaim(stripped, key)
	if err != nil || !hmac.Equal(q.canonical, comparison.canonical) {
		return fail()
	}
	participant := counterAdmissionParticipant(plan)
	if participant == nil || validateCommandCounters(participant, prepared, *plan.counters) != nil {
		return fail()
	}
	fp := claimFingerprint(key, q.canonical)
	snapshot := plan.snapshot()
	snapshot.Digest, err = FeaturePlanDigest(base.Binding, fp, snapshot)
	if err != nil {
		return fail()
	}
	admitted, err := c.registry.admitFeaturePlan(base.Binding, fp, snapshot)
	if err != nil {
		return fail()
	}
	return q, admitted, nil
}

// PrepareMFATOTPAttemptPlanWithOriginal freezes a native counter-enriched denial
// declaration while deriving journal identity only from original submitted
// intent and opaque code/browser custody. Only six validated native counter
// fields may be added; all other changes deny. It performs no IO or charging.
// Existing mapped-command APIs and generic fingerprint semantics are unchanged.
func (c *Coordinator) PrepareMFATOTPAttemptPlanWithOriginal(original, prepared identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareMFATOTPAttemptWithOriginal(original, prepared, p)
	return snapshot, err
}

func (c *Coordinator) prepareMFATOTPAttemptWithOriginal(original, prepared identity.Command, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	return c.prepareMFAAttemptWithOriginal(original, prepared, p, "identity.mfa.totp-verify")
}

func (c *Coordinator) prepareMFAAttemptWithOriginal(original, prepared identity.Command, p CommandPlan, operation string) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	f, ok := prepared.Feature()
	if !ok {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	_, _, admitted, err := c.prepareMFAAttempt(f.Binding, prepared, p, operation)
	if err != nil {
		return claimRequest{}, CommandPlan{}, nil, err
	}
	q, admitted, err := c.originalMFAClaim(original, prepared, admitted)
	if err != nil {
		return claimRequest{}, CommandPlan{}, nil, err
	}
	return q, admitted.snapshot(), admitted, nil
}

// PrepareMFATOTPFeaturePlanWithOriginal performs the same closed separation for
// retained session generation. The complete counter/child/lifecycle declaration
// remains frozen. Pass the exact pair to ExecutePreparedMFATOTPFeature; a current
// key or preparation time cannot replace historical command or plan evidence.
func (c *Coordinator) PrepareMFATOTPFeaturePlanWithOriginal(original, prepared identity.Command, p CommandPlan) (CommandPlan, error) {
	return c.prepareMFAFeaturePlanWithOriginal(original, prepared, p, "identity.mfa.totp-verify")
}

func (c *Coordinator) prepareMFAFeaturePlanWithOriginal(original, prepared identity.Command, p CommandPlan, operation string) (CommandPlan, error) {
	f, ok := prepared.Feature()
	if !ok || f.Operation.OperationID != operation {
		return CommandPlan{}, invalidPlan()
	}
	_, admitted, _, err := c.prepareFeaturePreparation(prepared, p)
	if err != nil {
		return CommandPlan{}, err
	}
	_, admitted, err = c.originalMFAClaim(original, prepared, admitted)
	if err != nil {
		return CommandPlan{}, err
	}
	return admitted.snapshot(), nil
}

// PrepareMFARecoveryAttemptPlanWithOriginal freezes validated counter enrichment
// while preserving the exact original recovery code, browser and public intent
// as journal identity. Only the six native counter fields may be added. No IO,
// comparison, charge, code consumption or session issuance occurs here.
func (c *Coordinator) PrepareMFARecoveryAttemptPlanWithOriginal(original, prepared identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareMFAAttemptWithOriginal(original, prepared, p, "identity.mfa.recovery-use")
	return snapshot, err
}

// PrepareMFARecoveryFeaturePlanWithOriginal freezes the native retained-session
// declaration while keeping original recovery/browser custody as journal intent.
// Counter/child/lifecycle validation remains mandatory. This does not consume
// the recovery code or grant a session; pass the exact pair to the corresponding
// ExecutePreparedMFARecoveryFeature method without replacing retained evidence.
func (c *Coordinator) PrepareMFARecoveryFeaturePlanWithOriginal(original, prepared identity.Command, p CommandPlan) (CommandPlan, error) {
	return c.prepareMFAFeaturePlanWithOriginal(original, prepared, p, "identity.mfa.recovery-use")
}

// PrepareMFAOTPFeaturePlanWithOriginal validates the exact native consuming OTP
// attempt and protected-counter enrichment while preserving submitted
// code/browser/public intent as journal identity. The native OTP owner must
// authenticate its encrypted custody; all other field changes deny.
// Original transport.network must match the counter network; it remains only
// in opaque original intent, not the stored preparation declaration.
// No IO, comparison, charge, generation or session issuance occurs. Execute the exact
// pair through ExecutePreparedMFAOTPFeature; retries cannot remap the attempt.
func (c *Coordinator) PrepareMFAOTPFeaturePlanWithOriginal(original, prepared identity.Command, p CommandPlan) (CommandPlan, error) {
	return c.prepareMFAFeaturePlanWithOriginal(original, prepared, p, "identity.mfa.otp-verify")
}
