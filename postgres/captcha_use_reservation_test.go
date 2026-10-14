package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type captchaUseReservationProbe struct {
	riskReservationProbe
	deny, panicValidation bool
}

func (p *captchaUseReservationProbe) ValidateCaptchaUseCommand(identity.Command, CaptchaEvidencePlan) error {
	if p.panicValidation {
		panic("private captcha diagnostic")
	}
	if p.deny {
		return identity.ForbiddenError{}
	}
	return nil
}
func (*captchaUseReservationProbe) ReserveCaptchaEvidence(context.Context, CaptchaUseReservationWork) error {
	return nil
}
func (*captchaUseReservationProbe) RebindCaptchaEvidence(context.Context, CaptchaUseReservationWork) error {
	return nil
}

func TestCaptchaUseReservationAdmissionOwnsPlanAndRejectsInvalidNativeInput(t *testing.T) {
	p := &captchaUseReservationProbe{}
	c, command, plan := riskReservationFixture(t, p)
	s, _ := command.Feature()
	_, custody := captchaUsePlanFixture(t)
	plan.CaptchaEvidence = custody.CaptchaEvidence
	plan.CaptchaEvidence.PolicyVersion = plan.RiskEvidence.PolicyVersion
	prepared, err := c.PrepareCommandPlan(s.Binding, command, plan)
	if err != nil {
		t.Fatal("complete reservation contributor rejected", err)
	}
	want := *prepared.CaptchaEvidence
	plan.CaptchaEvidence.Signature[0]++
	_, _, admitted, err := c.prepare(s.Binding, command, prepared)
	if err != nil || admitted.captchaUse == nil || *admitted.captchaUse != want {
		t.Fatal("consuming custody omitted", err)
	}
	snapshot := admitted.snapshot()
	snapshot.CaptchaEvidence.Signature[0]++
	if *admitted.captchaUse != want {
		t.Fatal("historical custody aliased snapshot")
	}
	p.deny = true
	if _, err := c.PrepareCommandPlan(s.Binding, command, prepared); err == nil {
		t.Fatal("native scope denial ignored")
	}
	p.deny, p.panicValidation = false, true
	if _, err := c.PrepareCommandPlan(s.Binding, command, prepared); err == nil {
		t.Fatal("native validation panic admitted")
	}
}

func TestCaptchaUseReservationZeroAndRedaction(t *testing.T) {
	var w CaptchaUseReservationWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero binding")
	}
	if _, err := w.NativeCommand(nil); err == nil {
		t.Fatal("zero native input")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero write")
	}
	if _, err := w.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero read")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero primary time")
	}
	for _, value := range []any{w, CaptchaUseReservationBinding{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("custody serialized")
		}
	}
	if fmt.Sprintf("%#v", w) != "postgres.CaptchaUseReservationWork(redacted)" {
		t.Fatal("authority leaked")
	}
}
