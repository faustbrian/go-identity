package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type mfaOTPAttemptProbe struct {
	mfaCompletionValidationParticipant
}
type mfaOTPNoBudgetProbe struct{ MFACompletionContributor }

func (*mfaOTPAttemptProbe) PrepareMFAOTPAttempt(context.Context, MFAOTPAttemptWork) (MFAAttemptDisposition, error) {
	return MFAAttemptUnchanged, nil
}
func (*mfaOTPAttemptProbe) RecordMFAOTPAttemptDenial(context.Context, MFAOTPAttemptWork) error {
	return nil
}

func TestMFAOTPAttemptRequiresBothRegisteredOwners(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, p := mfaCompletionPlanFixture(t, "otp-verify")
	op := p.Feature.Operation
	code, _ := auth.NewOneTimeCode("123456")
	command, err := identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "transport.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}}}}, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	owner := &mfaOTPAttemptProbe{mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, expected: command, proof: *p.Capability}, completion: *p.MFACompletion}}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &otpReservationProbe{}, &capabilityExecutionProbe{}}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry, p.Contributors = registry, registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := c.PrepareOTPAttemptPlan(b, command, p)
	if err != nil {
		t.Fatal("closed MFA/OTP counted declaration unavailable", err)
	}
	_, _, admitted, err := c.prepareOTPAttempt(b, command, prepared)
	if err != nil || mfaAttemptOwner(admitted) != owner {
		t.Fatal("OTP-only counted work omitted original shared MFA budget owner", err)
	}
	// Submitted code/browser define history; native custody and protected
	// counters enrich it without replacing that original identity.
	base, _ := command.Feature()
	mapped := base
	mapped.Fields = append(append([]identity.FeatureField(nil), base.Fields...), []identity.FeatureField{
		{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("synthetic-native-custody")}},
		{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
		{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}},
		{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-user"}},
		{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}},
		{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}},
		{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}},
	}...)
	makeMapped := func(s identity.FeatureCommandSpec, digits string) identity.Command {
		t.Helper()
		code, e := auth.NewOneTimeCode(digits)
		if e != nil {
			t.Fatal(e)
		}
		v, e := identity.NewFeatureOneTimeCodePreAuthCommand(s, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	enriched := makeMapped(mapped, "123456")
	owner.expected = enriched
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{9}}
	separated, err := c.PrepareMFAOTPFeaturePlanWithOriginal(command, enriched, p)
	if err != nil {
		t.Fatal("original OTP intent cannot be separated from native prepared attempt", err)
	}
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	digest, err := FeaturePlanDigest(b, claimFingerprint(c.keys.retained[c.keys.current], claim.canonical), separated)
	if err != nil || digest != separated.Digest {
		t.Fatal("native attempt replaced original journal fingerprint", err)
	}
	for _, mode := range []string{"code", "network", "extra-otp", "extra-counter", "changed-original", "missing-custody"} {
		bad := mapped
		bad.Fields = append([]identity.FeatureField(nil), mapped.Fields...)
		digits := "123456"
		switch mode {
		case "code":
			digits = "654321"
		case "network":
			for i := range bad.Fields {
				if bad.Fields[i].Name == "counter.network" {
					bad.Fields[i].Value.Text = "203.0.113.71"
				}
			}
		case "extra-otp":
			bad.Fields = append(bad.Fields, identity.FeatureField{Name: "otp.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		case "extra-counter":
			bad.Fields = append(bad.Fields, identity.FeatureField{Name: "counter.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		case "changed-original":
			bad.Fields = append(bad.Fields, identity.FeatureField{Name: "public.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		case "missing-custody":
			bad.Fields = bad.Fields[1:]
		}
		candidate := makeMapped(bad, digits)
		owner.expected = candidate
		if _, e := c.PrepareMFAOTPFeaturePlanWithOriginal(command, candidate, p); e == nil {
			t.Fatal("substituted native enrichment admitted", mode)
		}
	}
	owner.expected = command
	entries[3] = &mfaOTPNoBudgetProbe{&owner.mfaCompletionValidationParticipant}
	registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry, p.Contributors = registry, registry.Descriptors()
	if _, err := c.PrepareOTPAttemptPlan(b, command, p); err == nil {
		t.Fatal("MFA OTP attempt without shared-budget admission was accepted")
	}
}

func TestMFAOTPAttemptWorkZeroCannotReadChargeOrDisclose(t *testing.T) {
	var w MFAOTPAttemptWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero disclosed original continuation")
	}
	if _, err := w.NativeCommand(nil); err == nil {
		t.Fatal("zero disclosed code or cookie")
	}
	if _, err := w.Query(t.Context(), "SELECT 1"); err == nil {
		t.Fatal("zero read primary")
	}
	if _, err := w.Exec(t.Context(), "SELECT 1"); err == nil {
		t.Fatal("zero charged budget")
	}
	if _, err := w.DatabaseTime(t.Context()); err == nil {
		t.Fatal("zero sampled clock")
	}
	if _, err := w.ReserveCommandCounters(t.Context(), nil); err == nil {
		t.Fatal("zero reserved risk")
	}
	if err := w.RequireOTPDenial(nil); err == nil {
		t.Fatal("zero fabricated native OTP denial")
	}
	for _, v := range []any{w, MFAOTPAttemptBinding{}} {
		if _, err := json.Marshal(v); err == nil || !strings.Contains(fmt.Sprintf("%#v", v), "redacted") {
			t.Fatal("MFA OTP callback disclosed custody")
		}
	}
}
