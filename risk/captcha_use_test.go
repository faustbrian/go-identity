package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// This core test authenticates local custody, never durable issuance or use.
func TestCaptchaUsePreservesOriginalAndSeparatelyBindsConsumer(t *testing.T) {
	c, original, record := captchaNativeFixture(t, captchaFlowInput())
	now := record.IssuedAt.Add(time.Microsecond)
	c.Clock = func() time.Time { return now }
	c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
		t.Fatal("use precheck verified provider")
		return CaptchaObservation{}, nil
	}
	issuer, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := issuer.RestoreCaptchaIssue(original)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewFlowContext(captchaFlowInput())
	if err != nil {
		t.Fatal(err)
	}
	request := CaptchaEvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "consumer", Flow: flow, Reference: record.Reference}
	use, err := issuer.PrecheckUse(context.Background(), issue, request, record)
	if err != nil {
		t.Fatal("valid original rejected", err)
	}
	if err := use.Validate(request, now); err != nil {
		t.Fatal(err)
	}
	prepared := use.Prepared()
	if prepared.ConsumerCommandID != request.CommandID || prepared.ConsumerActor != request.Actor || prepared.Original.Binding.CommandID != original.Binding.CommandID || prepared.EvidenceDigest != record.EvidenceDigest || prepared.IssuedAt != record.IssuedAt || prepared.ExpiresAt != record.ExpiresAt || prepared.CheckedAt != now {
		t.Fatal("precheck changed original or consumer binding")
	}
	claim, err := c.Keys[0].RestoreCaptchaUse(prepared)
	if err != nil || claim.Validate(now) != nil {
		t.Fatal("signed use did not restore", err)
	}
	if _, err := issuer.RecheckUse(original, prepared, now); err != nil {
		t.Fatal("native primary-time recheck rejected", err)
	}
	// Native startup custody must recheck without an executable issuer or dummy
	// executor; otherwise composition would require an issuer/store cycle.
	custodyConfig := c
	custodyConfig.Clock, custodyConfig.Verify, custodyConfig.Executor = nil, nil, nil
	custody, err := NewCaptchaEvidenceCustody(custodyConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.RecheckUse(original, prepared, now); err != nil {
		t.Fatal("callback-free native custody rejected", err)
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), record.ExpiresAt, record.ExpiresAt.Add(time.Microsecond)} {
		if use.Validate(request, at) == nil || claim.Validate(at) == nil {
			t.Fatal("original exclusive interval not enforced")
		}
	}
	changed := request
	changed.Actor = "foreign"
	if use.Validate(changed, now) == nil {
		t.Fatal("consumer substitution accepted")
	}
	now = record.ExpiresAt
	if _, err := issuer.PrecheckUse(context.Background(), issue, request, record); !errors.Is(err, ErrInvalidEvidenceExecution) {
		t.Fatal("expired original accepted", err)
	}
}

func TestCaptchaUseRecheckRejectsForeignConfigurationOriginalAndNonprimaryTime(t *testing.T) {
	c, original, record := captchaNativeFixture(t, captchaFlowInput())
	now := record.IssuedAt.Add(time.Microsecond)
	c.Clock = func() time.Time { return now }
	s, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := s.RestoreCaptchaIssue(original)
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := NewFlowContext(captchaFlowInput())
	request := CaptchaEvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "consumer", Flow: flow, Reference: record.Reference}
	use, err := s.PrecheckUse(context.Background(), issue, request, record)
	if err != nil {
		t.Fatal(err)
	}
	p := use.Prepared()
	foreign := captchaFlowInput()
	foreign.ChallengeID += "-distinct"
	_, other, _ := captchaNativeFixture(t, foreign)
	changed := c
	changed.Tier = "different-valid-tier"
	foreignIssuer, err := NewCaptchaEvidenceIssuer(changed)
	if err != nil {
		t.Fatal(err)
	}
	foreignCustody, err := NewCaptchaEvidenceCustody(changed)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewCaptchaEvidenceCustody(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, recheck := range map[string]func(PreparedCaptchaEvidence, PreparedCaptchaEvidenceUse, time.Time) (CaptchaEvidenceUseClaim, error){
		"issuer": s.RecheckUse, "custody": custody.RecheckUse,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				original PreparedCaptchaEvidence
				now      time.Time
			}{
				{other, now}, {original, now.Add(time.Nanosecond)}, {original, now.In(time.FixedZone("nonprimary", 3600))}, {original, record.ExpiresAt},
			} {
				claim, err := recheck(tc.original, p, tc.now)
				if !errors.Is(err, ErrInvalidEvidenceExecution) || claim.state != nil {
					t.Fatal("invalid native recheck returned claim", err)
				}
			}
		})
	}
	for _, recheck := range []func(PreparedCaptchaEvidence, PreparedCaptchaEvidenceUse, time.Time) (CaptchaEvidenceUseClaim, error){foreignIssuer.RecheckUse, foreignCustody.RecheckUse, (CaptchaEvidenceCustody{}).RecheckUse} {
		claim, err := recheck(original, p, now)
		if !errors.Is(err, ErrInvalidEvidenceExecution) || claim.state != nil {
			t.Fatal("foreign current custody returned claim", err)
		}
	}
	newKey, err := NewEvidenceKey(2, bytes.Repeat([]byte{0x43}, 32), bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rotated := c
	rotated.Keys = append([]EvidenceKey{newKey}, c.Keys...)
	rotatedIssuer, err := NewCaptchaEvidenceIssuer(rotated)
	if err != nil {
		t.Fatal(err)
	}
	rotatedCustody, err := NewCaptchaEvidenceCustody(rotated)
	if err != nil {
		t.Fatal(err)
	}
	for _, recheck := range []func(PreparedCaptchaEvidence, PreparedCaptchaEvidenceUse, time.Time) (CaptchaEvidenceUseClaim, error){rotatedIssuer.RecheckUse, rotatedCustody.RecheckUse} {
		claim, err := recheck(original, p, now)
		if err != nil || claim.Prepared().Signature != p.Signature || claim.Prepared().ExpiresAt != record.ExpiresAt {
			t.Fatal("retained-key rotation changed original claim", err)
		}
	}
}

func TestCaptchaUseCancellationDuringClockReturnsZero(t *testing.T) {
	c, original, record := captchaNativeFixture(t, captchaFlowInput())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	c.Clock = func() time.Time {
		calls++
		if calls == 2 {
			cancel()
		}
		return record.IssuedAt.Add(time.Microsecond)
	}
	s, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := s.RestoreCaptchaIssue(original)
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := NewFlowContext(captchaFlowInput())
	request := CaptchaEvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "consumer", Flow: flow, Reference: record.Reference}
	use, err := s.PrecheckUse(ctx, issue, request, record)
	if !errors.Is(err, context.Canceled) || use.state != nil || calls != 2 {
		t.Fatal("mid-precheck cancellation returned custody", err)
	}
}

func TestCaptchaUseClosedFlowsTamperingAndOwnedCopies(t *testing.T) {
	base := captchaFlowInput()
	flows := []FlowContextInput{base, base, base, base, base, base}
	flows[1].Subject, flows[1].AnonymousFlow = "user", ""
	flows[2].Kind, flows[2].Subject, flows[2].AnonymousFlow, flows[2].PreAuthTransaction, flows[2].Session = FlowAuthenticated, "user", "", "", "session"
	flows[3].Kind, flows[3].Subject, flows[3].AnonymousFlow, flows[3].PreAuthTransaction, flows[3].Actor = FlowAdministrator, "user", "", "", "admin"
	flows[4].Kind, flows[4].PreAuthTransaction, flows[4].Actor = FlowAdministrator, "", "admin"
	flows[5] = flows[3]
	flows[5].Session = "session"
	for n, flowInput := range flows {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c, original, record := captchaNativeFixture(t, flowInput)
			now := record.IssuedAt.Add(time.Microsecond)
			c.Clock = func() time.Time { return now }
			s, err := NewCaptchaEvidenceIssuer(c)
			if err != nil {
				t.Fatal(err)
			}
			issue, err := s.RestoreCaptchaIssue(original)
			if err != nil {
				t.Fatal(err)
			}
			flow, _ := NewFlowContext(flowInput)
			actor := "consumer"
			if flowInput.Actor != "" {
				actor = flowInput.Actor
			}
			request := CaptchaEvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: actor, Flow: flow, Reference: record.Reference}
			use, err := s.PrecheckUse(context.Background(), issue, request, record)
			if err != nil {
				t.Fatal(err)
			}
			p := use.Prepared()
			for _, mutate := range []func(*PreparedCaptchaEvidenceUse){
				func(p *PreparedCaptchaEvidenceUse) { p.ConsumerCommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
				func(p *PreparedCaptchaEvidenceUse) { p.ConsumerActor += "-foreign" },
				func(p *PreparedCaptchaEvidenceUse) { p.EvidenceDigest[0] ^= 1 },
				func(p *PreparedCaptchaEvidenceUse) { p.Signature[0] ^= 1 },
				func(p *PreparedCaptchaEvidenceUse) { p.IssuedAt = p.IssuedAt.Add(time.Microsecond) },
				func(p *PreparedCaptchaEvidenceUse) { p.CheckedAt = p.CheckedAt.Add(time.Microsecond) },
				func(p *PreparedCaptchaEvidenceUse) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
				func(p *PreparedCaptchaEvidenceUse) {
					p.Original.Binding.Replay.Flow.RequestFingerprint = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
				},
				func(p *PreparedCaptchaEvidenceUse) {
					p.Original.Binding.Replay.Keys[0].Fingerprint = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
				},
			} {
				copy := use.Prepared()
				mutate(&copy)
				if _, err := c.Keys[0].RestoreCaptchaUse(copy); err == nil {
					t.Fatal("altered signed use accepted")
				}
				if use.Prepared().Original.Binding.Replay.Keys[0] != p.Original.Binding.Replay.Keys[0] {
					t.Fatal("caller mutation changed owned aliases")
				}
			}
			for _, changed := range []CaptchaEvidenceUseRequest{
				{}, {CommandID: original.Binding.CommandID, Actor: actor, Flow: flow, Reference: record.Reference},
				{CommandID: request.CommandID, Actor: actor, Flow: flow, Reference: CaptchaEvidenceRef{}},
			} {
				if _, err := s.PrecheckUse(context.Background(), issue, changed, record); err == nil {
					t.Fatal("invalid consuming input accepted")
				}
			}
			foreign := flowInput
			foreign.ChallengeID += "-foreign"
			request.Flow, _ = NewFlowContext(foreign)
			if _, err := s.PrecheckUse(context.Background(), issue, request, record); err == nil {
				t.Fatal("foreign flow accepted")
			}
			request.Flow = flow
			wrong := c.Keys[0]
			wrong.digest[0] ^= 1
			if _, err := wrong.RestoreCaptchaUse(p); err == nil {
				t.Fatal("wrong linkage key accepted")
			}
			wrong = c.Keys[0]
			wrong.signing[0] ^= 1
			if _, err := wrong.RestoreCaptchaUse(p); err == nil {
				t.Fatal("wrong integrity key accepted")
			}
			claim, err := c.Keys[0].RestoreCaptchaUse(p)
			if err != nil {
				t.Fatal(err)
			}
			copy := claim.Prepared()
			copy.Original.Binding.Replay.Keys[0].Fingerprint = "mutated"
			if claim.Prepared().Original.Binding.Replay.Keys[0] != p.Original.Binding.Replay.Keys[0] {
				t.Fatal("claim projection shares aliases")
			}
			for _, value := range []any{request, use, p, claim} {
				if strings.Contains(fmt.Sprintf("%#v", value), record.Reference.Reveal()) {
					t.Fatal("diagnostics leaked bearer")
				}
				if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
					t.Fatal("sensitive use serialized", err)
				}
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := s.PrecheckUse(cancelled, issue, request, record); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation not preserved", err)
			}
			if _, err := s.PrecheckUse(nil, issue, request, record); err == nil {
				t.Fatal("nil context accepted")
			}
			if _, err := (EvidenceKey{}).RestoreCaptchaUse(p); err == nil {
				t.Fatal("zero key accepted")
			}
			if (CaptchaEvidenceUse{}).Validate(request, now) == nil || (CaptchaEvidenceUseClaim{}).Validate(now) == nil {
				t.Fatal("zero proof accepted")
			}
		})
	}
}
