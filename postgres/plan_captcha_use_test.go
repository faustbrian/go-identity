package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func captchaUsePlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "protected"
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1})
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	p.CaptchaEvidence = &CaptchaEvidencePlan{IssuanceCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", KeyVersion: 1, PolicyVersion: 3, OriginalSignature: [32]byte{1}, EvidenceDigest: [32]byte{2}, Signature: [32]byte{3}, IssuedAt: at, CheckedAt: at.Add(time.Nanosecond), ExpiresAt: at.Add(time.Minute)}
	if p.CaptchaEvidence.IssuanceCommandID == string(s.Binding.CommandID) {
		t.Fatal("fixture identities collide")
	}
	return s.Binding, p
}

func TestCaptchaUsePlanConservesCustodyAndBindsEveryField(t *testing.T) {
	b, p := captchaUsePlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("typed consuming declaration unavailable", err)
	}
	want := sha256.Sum256(wire)
	decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	p.Digest = want
	if err != nil || !reflect.DeepEqual(decoded, p) {
		t.Fatal("historical consuming custody changed", err)
	}
	for _, change := range []func(*CaptchaEvidencePlan){
		func(p *CaptchaEvidencePlan) { p.IssuanceCommandID = "AgICAgICAgICAgICAgICAg" },
		func(p *CaptchaEvidencePlan) { p.KeyVersion++ },
		func(p *CaptchaEvidencePlan) { p.PolicyVersion++ },
		func(p *CaptchaEvidencePlan) { p.OriginalSignature[0]++ },
		func(p *CaptchaEvidencePlan) { p.EvidenceDigest[0]++ },
		func(p *CaptchaEvidencePlan) { p.Signature[0]++ },
		func(p *CaptchaEvidencePlan) { p.IssuedAt = p.IssuedAt.Add(time.Microsecond) },
		func(p *CaptchaEvidencePlan) { p.CheckedAt = p.CheckedAt.Add(time.Microsecond) },
		func(p *CaptchaEvidencePlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
	} {
		copy := *p.CaptchaEvidence
		copy.CheckedAt = copy.CheckedAt.Add(time.Second)
		altered := p
		altered.CaptchaEvidence = &copy
		// Compare mutations against this independently valid baseline, not the
		// original nanosecond check that could precede a changed issuance instant.
		base, err := FeaturePlanDigest(b, [32]byte{1}, altered)
		if err != nil {
			t.Fatal(err)
		}
		change(&copy)
		got, err := FeaturePlanDigest(b, [32]byte{1}, altered)
		if err != nil || got == base {
			t.Fatal("consuming field omitted from fingerprint", err)
		}
	}
	decoded.CaptchaEvidence.Signature[0]++
	if decoded.CaptchaEvidence.Signature == p.CaptchaEvidence.Signature {
		t.Fatal("historical projection aliases input")
	}
	if _, err := KernelPlanDigest(b, [32]byte{1}, p); err == nil {
		t.Fatal("kernel silently omitted consuming declaration")
	}
	if _, err := json.Marshal(*p.CaptchaEvidence); err == nil {
		t.Fatal("private linkage serialized")
	}
	for _, changed := range [][]byte{append(bytes.Clone(wire), 0), bytes.Replace(wire, []byte("identity-feature-captcha-use-v1"), []byte("identity-feature-captcha-use-v2"), 1)} {
		if got, err := decodeFeaturePlan(b, [32]byte{1}, changed); err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("foreign consuming wire decoded")
		}
	}
	for end := range len(wire) {
		if got, err := decodeFeaturePlan(b, [32]byte{1}, wire[:end]); err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("truncated consuming wire decoded")
		}
	}
}

func TestCaptchaUsePlanRejectsMissingOrConflictingCustody(t *testing.T) {
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CaptchaEvidence.IssuanceCommandID = "" },
		func(p *CommandPlan) { p.CaptchaEvidence.KeyVersion = 0 },
		func(p *CommandPlan) { p.CaptchaEvidence.PolicyVersion = 0 },
		func(p *CommandPlan) { p.CaptchaEvidence.OriginalSignature = [32]byte{} },
		func(p *CommandPlan) { p.CaptchaEvidence.EvidenceDigest = [32]byte{} },
		func(p *CommandPlan) { p.CaptchaEvidence.Signature = [32]byte{} },
		func(p *CommandPlan) { p.CaptchaEvidence.IssuedAt = time.Time{} },
		func(p *CommandPlan) { p.CaptchaEvidence.CheckedAt = p.CaptchaEvidence.ExpiresAt },
		func(p *CommandPlan) { p.CaptchaEvidence.ExpiresAt = p.CaptchaEvidence.IssuedAt },
		func(p *CommandPlan) {
			p.CaptchaEvidence.ExpiresAt = p.CaptchaEvidence.IssuedAt.Add(2*time.Minute + time.Microsecond)
		},
		func(p *CommandPlan) { p.Contributors = p.Contributors[:4] },
		func(p *CommandPlan) { p.CaptchaReplayReservation = true },
	} {
		b, p := captchaUsePlanFixture(t)
		change(&p)
		if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
			t.Fatal("incomplete or conflicting consuming declaration accepted")
		}
	}
	b, p := captchaUsePlanFixture(t)
	p.CaptchaEvidence.IssuanceCommandID = string(b.CommandID)
	if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
		t.Fatal("issuance command used as consumer")
	}
}

func TestCaptchaUsePlanSharesRiskOwnerWithCountersAndPhoneEvidence(t *testing.T) {
	for _, phone := range []bool{false, true} {
		b, p := captchaUsePlanFixture(t)
		if phone {
			_, command, original := riskReservationFixture(t, &riskReservationProbe{})
			s, _ := command.Feature()
			original.CaptchaEvidence = p.CaptchaEvidence
			original.CaptchaEvidence.PolicyVersion = original.RiskEvidence.PolicyVersion
			b, p = s.Binding, original
		} else {
			p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{4}}
		}
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal("shared owner declaration rejected", err)
		}
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		p.Digest = sha256.Sum256(wire)
		if err != nil || !reflect.DeepEqual(decoded, p) {
			t.Fatal("shared role dropped during historical decoding", err)
		}
		copy := *p.CaptchaEvidence
		copy.Signature[0]++
		p.CaptchaEvidence = &copy
		changed, err := FeaturePlanDigest(b, [32]byte{1}, p)
		if err != nil || changed == decoded.Digest {
			t.Fatal("shared role consuming signature omitted", err)
		}
		p.CaptchaEvidence.PolicyVersion++
		if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
			t.Fatal("shared risk owner admitted conflicting policy versions")
		}
		p.CaptchaEvidence.PolicyVersion--
		p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1})
		if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
			t.Fatal("duplicated risk owner admitted")
		}
	}
}

func TestCaptchaUsePlanCannotEnableIncompleteExecution(t *testing.T) {
	c, command, p := riskReservationFixture(t, &riskReservationProbe{})
	s, _ := command.Feature()
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err != nil {
		t.Fatal("supported sibling preparation rejected", err)
	}
	_, declaration := captchaUsePlanFixture(t)
	p.CaptchaEvidence = declaration.CaptchaEvidence
	p.CaptchaEvidence.PolicyVersion = p.RiskEvidence.PolicyVersion
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err == nil || !reflect.DeepEqual(prepared, CommandPlan{}) {
		t.Fatal("structural custody enabled incomplete consuming execution")
	}
	p.Digest, err = FeaturePlanDigest(s.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal("valid structural declaration rejected", err)
	}
	reservation, result, err := c.ReserveCommand(context.Background(), s.Binding, command, p)
	if err == nil || reservation.state != nil || result != (identity.CommandResult{}) {
		t.Fatal("structural custody obtained reservation authority")
	}
}

func TestCaptchaUsePlanKernelPreparationAndReservationRejectCustody(t *testing.T) {
	c, command, plan := coordinatorFixture(t)
	prepared, err := c.PrepareCommandPlan(codecBinding(), command, plan)
	if err != nil {
		t.Fatal("supported kernel plan rejected", err)
	}
	_, declaration := captchaUsePlanFixture(t)
	for _, custody := range []*CaptchaEvidencePlan{{}, declaration.CaptchaEvidence} {
		t.Run(fmt.Sprintf("key-version-%d", custody.KeyVersion), func(t *testing.T) {
			altered := prepared
			altered.CaptchaEvidence = custody
			got, err := c.PrepareCommandPlan(codecBinding(), command, altered)
			var invalid identity.InvalidInputError
			if !errors.As(err, &invalid) || invalid.Field != "command_plan" || !reflect.DeepEqual(got, CommandPlan{}) {
				t.Error("kernel preparation silently discarded CAPTCHA custody", err)
			}
			reservation, result, err := c.ReserveCommand(context.Background(), codecBinding(), command, altered)
			if !errors.As(err, &invalid) || invalid.Field != "command_plan" || reservation.state != nil || result != (identity.CommandResult{}) {
				t.Error("kernel reservation passed custody rejection boundary", err)
			}
		})
	}
}
