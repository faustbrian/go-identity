package postgres

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestMFAOTPPreparationRetainsNativeAttemptBeforeGeneration(t *testing.T) {
	b, p := mfaCompletionPlanFixture(t, "otp-verify")
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{9}}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{
		{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("synthetic-authenticated-native-attempt")}},
		{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}},
		{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}},
		{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-user"}},
		{Name: "transport.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "203.0.113.71"}},
		{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "203.0.113.71"}},
		{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}},
		{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}},
		{Name: "original.intent", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: false}},
		{Name: "original.signed", Value: identity.FeatureValue{Kind: identity.FeatureInt64, Int64: -42}},
	}}
	c, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ = c.Feature()
	original := spec
	original.Fields = nil
	for _, field := range spec.Fields {
		if !strings.HasPrefix(field.Name, "otp.") && !strings.HasPrefix(field.Name, "counter.") {
			original.Fields = append(original.Fields, field)
		}
	}
	fp := [32]byte{1}
	wire, err := encodeMFAOTPPreparation(spec, fp, p)
	if err != nil {
		t.Fatal("native attempt cannot be retained before session generation", err)
	}
	if bytes.Contains(wire, []byte("203.0.113.71")) {
		t.Fatal("checkpoint persisted raw network instead of original keyed intent")
	}
	t.Run("preparation-only-history", func(t *testing.T) {
		claim, err := prepareClaim(c, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		q, _ := queryInputs(b)
		state, profile := "pending", int16(4)
		now := time.Now().UTC().Truncate(time.Microsecond)
		until := now.Add(time.Second)
		observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, fingerprint: fp[:], state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
		for _, instant := range []time.Time{now, until.Add(time.Second)} {
			observed.now = instant
			result, err := commandReceipt(q, observed, nil)
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != b || result.Feature == nil || result.Feature.Operation != p.Feature.Operation || result.Validate() != nil {
				t.Fatal("unattached preparation lost bounded historical observation", err)
			}
		}
		for _, mutate := range []func(*commandObservation){
			func(o *commandObservation) { o.declaration = nil },
			func(o *commandObservation) { o.declaration = wire[:len(wire)-1] },
			func(o *commandObservation) { o.fingerprint = bytes.Repeat([]byte{2}, 32) },
			func(o *commandObservation) { o.preparationProfile = nil },
			func(o *commandObservation) { v := int16(2); o.preparationProfile = &v },
			func(o *commandObservation) { v := "committed"; o.state = &v },
			func(o *commandObservation) { o.plan = []byte{} },
		} {
			bad := observed
			mutate(&bad)
			if result, err := commandReceipt(q, bad, nil); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("incomplete or corrupt preparation granted a historical outcome")
			}
		}
		state, class, version := "aborted", "dependency-failure", int32(1)
		observed.state, observed.class, observed.resultVersion = &state, &class, &version
		observed.result, err = encodeJournalResult(claim, featureOutcome(b, &spec.Operation, identity.CommitOutcomeNotCommitted, 0))
		if err != nil {
			t.Fatal(err)
		}
		result, err := commandReceipt(q, observed, nil)
		if !errors.As(err, new(identity.UnavailableError)) || result.Outcome != identity.CommitOutcomeNotCommitted || result.Binding != b || result.Validate() != nil {
			t.Fatal("audited preparation abort lost terminal failure history", err)
		}
	})
	got, plan, err := decodeMFAOTPPreparation(b, fp, wire)
	if err != nil || plan.OTP == nil || *plan.OTP != *p.OTP || plan.MFACompletion == nil || *plan.MFACompletion != *p.MFACompletion {
		t.Fatal("original attempt/continuation/counter identity changed", err)
	}
	complete, err := restoreMFAOTPPreparationSpec(original, got, plan)
	if err != nil || !reflect.DeepEqual(complete, spec) {
		t.Fatal("keyed original intent and retained metadata did not reconstruct exact command", err)
	}
	again, err := encodeMFAOTPPreparation(complete, fp, plan)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("noncanonical declaration", err)
	}
	got.Fields[0].Value.Bytes[0] ^= 1
	restored, _, err := decodeMFAOTPPreparation(b, fp, wire)
	if err != nil || reflect.DeepEqual(restored, got) {
		t.Fatal("returned fields alias retained attempt", err)
	}
	full, err := restoreMFAOTPPreparationSpec(original, restored, p)
	if err != nil || !reflect.DeepEqual(full, spec) {
		t.Fatal("returned byte mutation changed retained original command", err)
	}
	for i := range wire {
		if _, _, err := decodeMFAOTPPreparation(b, fp, wire[:i]); err == nil {
			t.Fatal("truncated declaration admitted", i)
		}
	}
	if _, _, err := decodeMFAOTPPreparation(b, [32]byte{2}, wire); err == nil {
		t.Fatal("foreign original fingerprint admitted")
	}
	if _, _, err := decodeMFAOTPPreparation(b, fp, append(wire, 0)); err == nil {
		t.Fatal("trailing declaration bytes admitted")
	}
	bad := p
	bad.OTP = nil
	if _, err := encodeMFAOTPPreparation(spec, fp, bad); err == nil {
		t.Fatal("missing native consuming attempt retained")
	}
}
