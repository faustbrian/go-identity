package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type otpExecutionProbe struct{ otpReservationProbe }

func (*otpExecutionProbe) CheckOTP(context.Context, OTPApplyWork) error       { return nil }
func (*otpExecutionProbe) FinalizeOTP(context.Context, OTPFinalizeWork) error { return nil }
func (*otpExecutionProbe) ReleaseOTP(context.Context, OTPReleaseWork) error   { return nil }

func TestOTPExecutionZeroAndPhaseCustody(t *testing.T) {
	owner := &otpExecutionProbe{}
	if _, err := (RecoveryWork{}).OTPBinding(owner); err == nil {
		t.Fatal("zero recovery disclosed OTP custody")
	}
	read, write, release := OTPApplyWork{}, OTPFinalizeWork{}, OTPReleaseWork{}
	for _, binding := range []func(OTPReservationContributor) (OTPReservationBinding, error){read.Binding, write.Binding, release.Binding} {
		if _, err := binding(owner); err == nil {
			t.Fatal("zero disclosed private linkage")
		}
	}
	for _, query := range []func(context.Context, string, ...any) (*WorkRows, error){read.Query, write.Query, release.Query} {
		if _, err := query(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("zero queried primary")
		}
	}
	for _, exec := range []func(context.Context, string, ...any) (int64, error){write.Exec, release.Exec} {
		if _, err := exec(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("zero mutated primary")
		}
	}
	for _, spec := range []func(OTPReservationContributor) (identity.FeatureCommandSpec, error){read.CommandSpec, write.CommandSpec} {
		if _, err := spec(owner); err == nil {
			t.Fatal("zero disclosed native scope")
		}
	}
	for _, value := range []any{read, write, release} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("invocation authority exported")
		}
	}
	var _ OTPExecutionContributor = owner
}
