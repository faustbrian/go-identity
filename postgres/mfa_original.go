package postgres

import (
	"crypto/hmac"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// Keep submitted intent and server-prepared counter state separate only for
// the closed native anonymous TOTP profile. Generic claim codecs stay exact.
// Native counter validation and the complete frozen plan still bind every
// prepared counter field; nothing permits replacing an existing declaration.
func (c *Coordinator) originalMFAClaim(original, prepared identity.Command, plan *admittedKernelPlan) (claimRequest, *admittedKernelPlan, error) {
	fail := func() (claimRequest, *admittedKernelPlan, error) { return claimRequest{}, nil, invalidPlan() }
	if c == nil || c.registry == nil || plan == nil || plan.counters == nil || plan.feature == nil || plan.feature.Operation.OperationID != "identity.mfa.totp-verify" || !validMFACompletionPlan(plan.binding, plan.snapshot()) {
		return fail()
	}
	base, baseOK := original.Feature()
	full, fullOK := prepared.Feature()
	code, codeOK := prepared.OneTimeCode()
	cookie, cookieOK := prepared.PreAuthCookie()
	if !baseOK || !fullOK || !codeOK || !cookieOK || base.Binding != full.Binding || base.Operation != full.Operation || base.Binding != plan.binding || full.Operation != plan.feature.Operation {
		return fail()
	}
	for _, field := range base.Fields {
		if strings.HasPrefix(field.Name, "counter.") {
			return fail()
		}
	}
	filtered := full
	filtered.Fields = nil
	count := 0
	for _, field := range full.Fields {
		if strings.HasPrefix(field.Name, "counter.") {
			switch field.Name {
			case "counter.network", "counter.session", "counter.subject", "counter.capability", "counter.prepared-at", "counter.key-versions":
				count++
			default:
				return fail()
			}
		} else {
			filtered.Fields = append(filtered.Fields, field)
		}
	}
	if count != 6 {
		return fail()
	}
	stripped, err := identity.NewFeatureOneTimeCodePreAuthCommand(filtered, code, cookie)
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
	f, ok := prepared.Feature()
	if !ok {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	_, _, admitted, err := c.prepareMFATOTPAttempt(f.Binding, prepared, p)
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
