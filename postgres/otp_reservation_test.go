package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

type otpReservationProbe struct{ otpAttemptProbe }

func (*otpReservationProbe) ReserveOTP(context.Context, OTPReservationWork) error { return nil }
func (*otpReservationProbe) RebindOTP(context.Context, OTPReservationWork) error  { return nil }

func TestOTPReservationPreparationRequiresConsumingNativeOwner(t *testing.T) {
	owner := &otpReservationProbe{}
	c, command, p := otpAttemptFixture(t, owner)
	s, _ := command.Feature()
	prepared, err := c.PrepareOTPReservationPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal("native consuming owner rejected", err)
	}
	p.OTP.ScopeDigest[0]++
	if *prepared.OTP == *p.OTP {
		t.Fatal("frozen plan aliases caller")
	}
	check := prepared
	check.OTP = cloneOTPPlan(prepared.OTP)
	check.OTP.Mode = OTPCheck
	if _, err := c.PrepareOTPReservationPlan(s.Binding, command, check); err == nil {
		t.Fatal("nonconsuming check admitted")
	}
	c, command, p = otpAttemptFixture(t, &otpAttemptProbe{})
	s, _ = command.Feature()
	if _, err := c.PrepareOTPReservationPlan(s.Binding, command, p); err == nil {
		t.Fatal("denial-only owner admitted")
	}
	if _, _, err := c.ReserveOTPCommand(context.Background(), s.Binding, command, p); err == nil {
		t.Fatal("denial-only owner reached SQL")
	}
}

func TestOTPReservationZeroAndRedaction(t *testing.T) {
	var w OTPReservationWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero binding")
	}
	if _, err := w.NativeCommand(nil); err == nil {
		t.Fatal("zero code custody")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero writes")
	}
	if _, err := w.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero reads")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero time")
	}
	for _, v := range []any{w, OTPReservationBinding{}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("private custody serialized")
		}
	}
	if fmt.Sprintf("%#v", w) != "postgres.OTPReservationWork(redacted)" {
		t.Fatal("private work exposed")
	}
	var _ OTPReservationContributor = (*otpReservationProbe)(nil)
}
