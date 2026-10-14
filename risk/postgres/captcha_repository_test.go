package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestCaptchaRepositoryAuthenticatesSelectedNativeProfile(t *testing.T) {
	issue, key, profile := captchaConfiguredFixture(t, captchaFlowFixture(), time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	custody, err := risk.NewCaptchaEvidenceCustody(profile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CaptchaCustody: []risk.CaptchaEvidenceCustody{custody}}
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := MapCaptchaIssue(issue, captchaCommandBinding(issue.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.FeatureOperations()) != 3 {
		t.Fatal("selected native CAPTCHA schemas are missing")
	}
	spec, _ := cmd.Feature()
	plan := identitypostgres.CommandPlan{SubjectType: "captcha_evidence", CaptchaReplayReservation: true, Feature: &identitypostgres.FeatureRegistration{Contributor: r.Descriptor(), Operation: spec.Operation}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.captcha.issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.captcha.verify", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "protected", RetentionPolicyVersion: 1}}}
	if err := r.ValidateFeatureCommand(cmd, plan); err != nil {
		t.Fatal("native CAPTCHA plan rejected", err)
	}
	for _, mutate := range []func(*identitypostgres.CommandPlan){
		func(p *identitypostgres.CommandPlan) { p.CaptchaReplayReservation = false },
		func(p *identitypostgres.CommandPlan) { p.SubjectType = "risk_evidence" },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.EventType = "risk.evidence_issued.v1" },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].EventType = "identity.risk.decide" },
	} {
		wrong := plan
		l := *plan.Lifecycle
		wrong.Lifecycle = &l
		wrong.Audits = append([]identitypostgres.AuditPlan(nil), plan.Audits...)
		mutate(&wrong)
		if r.ValidateFeatureCommand(cmd, wrong) == nil {
			t.Fatal("altered native CAPTCHA plan admitted")
		}
	}
	restored, err := r.restoreCaptcha(cmd)
	if err != nil || !reflect.DeepEqual(restored.Prepared(), issue.Prepared()) {
		t.Fatal("selected profile rejected original native custody", err)
	}
	// Startup configuration is owned, not a mutable consumer registration list.
	cfg.CaptchaCustody[0] = risk.CaptchaEvidenceCustody{}
	if _, err := r.restoreCaptcha(cmd); err != nil {
		t.Fatal("caller changed selected profile", err)
	}
	profile.Hostnames = []string{"other.example"}
	foreign, err := risk.NewCaptchaEvidenceCustody(profile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CaptchaCustody = []risk.CaptchaEvidenceCustody{foreign}
	wrong, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.restoreCaptcha(cmd); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("signature alone accepted foreign current configuration")
	}
	for _, profiles := range [][]risk.CaptchaEvidenceCustody{{{}}, make([]risk.CaptchaEvidenceCustody, 33)} {
		cfg.CaptchaCustody = profiles
		if _, err := NewRepository(cfg); !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("unbounded or zero selected custody")
		}
	}
	if _, err := r.ApplyFeature(context.Background(), identitypostgres.Work{}, cmd); err == nil {
		t.Fatal("zero domain authority admitted")
	}
	if err := r.ReserveCaptchaReplay(context.Background(), identitypostgres.CaptchaReservationWork{}); err == nil {
		t.Fatal("zero replay reservation admitted")
	}
	if err := r.RebindCaptchaReplay(context.Background(), identitypostgres.CaptchaReservationWork{}); err == nil {
		t.Fatal("zero replay takeover admitted")
	}
}
