package postgres

import (
	"context"
	"testing"
)

func TestFeatureExecutionPlanPreservesSubjectAndHistoricalProfile(t *testing.T) {
	_, command, p := featurePlanFixture(t)
	spec, _ := command.Feature()
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "standard"
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || decoded.SubjectType != "session" {
		t.Fatal("feature subject lost", err)
	}
	changed := p
	changed.SubjectType = "credential"
	digest, err := FeaturePlanDigest(spec.Binding, [32]byte{1}, changed)
	if err != nil || digest == decoded.Digest {
		t.Fatal("feature subject not bound", err)
	}
	for _, subject := range []string{"", "Session", "session.secret", string(make([]byte, 97))} {
		changed.SubjectType = subject
		if subject == "" {
			continue
		} // v1 remains a structural-only historical profile.
		if _, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, changed); err == nil {
			t.Fatal("invalid subject accepted")
		}
	}
}

func TestFeatureExecutionPlanBindsRetention(t *testing.T) {
	_, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "standard"
	a, err := FeaturePlanDigest(s.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].RetentionClass = "protected"
	b, err := FeaturePlanDigest(s.Binding, [32]byte{1}, p)
	if err != nil || a == b {
		t.Fatal("retention selection not bound", err)
	}
	for _, bad := range []string{"", "Protected", "unknown"} {
		p.Audits[0].RetentionClass = bad
		if _, err := FeaturePlanDigest(s.Binding, [32]byte{1}, p); err == nil {
			t.Fatal("invalid native retention accepted")
		}
	}
}

func TestFeatureExecutionRequiresOwnedUsableWork(t *testing.T) {
	c, command, _ := featurePlanFixture(t)
	if _, err := c.ApplyFeature(context.Background(), Work{}, command); err == nil {
		t.Fatal("zero Work applied feature")
	}
}

func TestRecoveryAuditPlansRejectsZeroAuthority(t *testing.T) {
	if plans, err := (RecoveryWork{}).AuditPlans(); err == nil || plans != nil {
		t.Fatal("zero authority disclosed frozen audit slots")
	}
}
